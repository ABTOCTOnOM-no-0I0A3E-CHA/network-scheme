package registry

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

/*
checkCatalog insists that every registry table is still the plain table the
migration created: an ordinary table without children, rules, row-level
security, policies or any non-internal trigger, with exactly the expected
columns, types, defaults and collations, no generated column, exactly the
expected CHECK, UNIQUE and primary key constraints (no foreign key in either
direction: a CHECK or an index can call a function on every written row)
and exactly the expected indexes; and that exec.audit_head
holds its one row. A trigger, rule, view or policy could make the database
show or store something else than what the executor writes (security.md
5.1a), so any deviation is tampering. Runs in the caller's transaction
after pinSession.
*/
func checkCatalog(ctx context.Context, q pgx.Tx) error {
	names := make([]string, len(tables))
	for i, t := range tables {
		names[i] = t.name
	}
	rows, err := q.Query(ctx, `
		SELECT c.relname::text, c.relkind = 'r' AND NOT c.relispartition AND NOT c.relhassubclass
			AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_trigger g WHERE g.tgrelid = c.oid AND NOT g.tgisinternal)
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_rewrite w WHERE w.ev_class = c.oid)
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid)
			AND NOT EXISTS (SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid = c.oid),
			(SELECT pg_catalog.string_agg(x.part, ',' ORDER BY x.part COLLATE "C") FROM (
				SELECT a.attname::text || ' ' || pg_catalog.format_type(a.atttypid, a.atttypmod) || ' ' ||
					a.attidentity::text || a.attgenerated::text || ' ' ||
					COALESCE(pg_catalog.pg_get_expr(d.adbin, d.adrelid), '') || ' ' ||
					COALESCE((SELECT co.collname::text FROM pg_catalog.pg_collation co WHERE co.oid = a.attcollation), '') AS part
				FROM pg_catalog.pg_attribute a
				LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
				WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) x),
			(SELECT pg_catalog.string_agg(k.conname::text || ' ' || k.contype::text || ' ' ||
					(k.conrelid = c.oid)::text || ' ' || pg_catalog.pg_get_constraintdef(k.oid), '; '
					ORDER BY k.conname::text COLLATE "C")
				FROM pg_catalog.pg_constraint k WHERE k.conrelid = c.oid OR k.confrelid = c.oid),
			(SELECT pg_catalog.string_agg(pg_catalog.pg_get_indexdef(i.indexrelid), '; '
					ORDER BY pg_catalog.pg_get_indexdef(i.indexrelid) COLLATE "C")
				FROM pg_catalog.pg_index i WHERE i.indrelid = c.oid)
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'exec' AND c.relname = ANY ($1::text[])`, names)
	if err != nil {
		return fmt.Errorf("registry: read catalog: %w", err)
	}
	seen := map[string]bool{}
	for rows.Next() {
		var name string
		var plain bool
		var cols, cons, idx *string
		if err := rows.Scan(&name, &plain, &cols, &cons, &idx); err != nil {
			rows.Close()
			return fmt.Errorf("registry: read catalog: %w", err)
		}
		t := lookup(name)
		switch {
		case t == nil || seen[name]:
			rows.Close()
			return tampered("catalog: unexpected relation %s", name)
		case !plain:
			rows.Close()
			return tampered("catalog: %s is not a plain table (trigger, rule, policy, RLS, inheritance or kind)", name)
		case cols == nil || *cols != t.fingerprint():
			rows.Close()
			return tampered("catalog: columns of %s changed", name)
		case cons == nil || *cons != expectedConstraints[name]:
			rows.Close()
			return tampered("catalog: constraints of %s changed", name)
		case idx == nil || *idx != expectedIndexes[name]:
			rows.Close()
			return tampered("catalog: indexes of %s changed", name)
		}
		seen[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("registry: read catalog: %w", err)
	}
	if len(seen) != len(tables) {
		return tampered("catalog: a registry table is missing")
	}
	var heads int64
	if err := q.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM exec.audit_head`).Scan(&heads); err != nil {
		return fmt.Errorf("registry: read audit_head: %w", err)
	}
	if heads != 1 {
		return tampered("audit_head has %d rows", heads)
	}
	return nil
}
