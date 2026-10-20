package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

/* maxGroupDepth caps the recursion of VisibleGroups so a corrupted cycle fails instead of hanging. */
const maxGroupDepth = 64

/*
HoldsAnywhere reports whether any binding, global or group, grants p. It is
the admission check of group-scoped routes; the object check follows in the
handler.
*/
func (s Subject) HoldsAnywhere(p Perm) bool {
	if p == PermSelf {
		return true
	}
	return slices.ContainsFunc(s.Bindings, func(b Binding) bool { return slices.Contains(matrix[b.Role], p) })
}

/*
VisibleGroups resolves where subj holds p: all is true for a global binding,
otherwise ids lists the bound groups and all their descendants (distinct,
unordered). A group tree deeper than 64 levels, in practice a corrupted
cycle, is an error.
*/
func (s *Store) VisibleGroups(ctx context.Context, subj Subject, p Perm) (all bool, ids []int64, err error) {
	var roots []int64
	for _, b := range subj.Bindings {
		if !slices.Contains(matrix[b.Role], p) {
			continue
		}
		if b.GroupID == nil {
			return true, nil, nil
		}
		roots = append(roots, *b.GroupID)
	}
	if len(roots) == 0 {
		return false, nil, nil
	}
	rows, err := s.pool.Query(ctx, `
WITH RECURSIVE t (id, depth) AS (
    SELECT id, 0 FROM core.device_group WHERE id = ANY($1)
  UNION ALL
    SELECT g.id, t.depth + 1 FROM core.device_group g JOIN t ON g.parent_id = t.id WHERE t.depth <= $2
)
SELECT id, depth FROM t`, roots, maxGroupDepth)
	if err != nil {
		return false, nil, fmt.Errorf("rbac: visible groups: %w", err)
	}
	defer rows.Close()
	seen := map[int64]struct{}{}
	for rows.Next() {
		var id int64
		var depth int
		if err := rows.Scan(&id, &depth); err != nil {
			return false, nil, fmt.Errorf("rbac: visible groups: %w", err)
		}
		if depth > maxGroupDepth {
			return false, nil, errors.New("rbac: visible groups: hierarchy deeper than 64 levels (cycle?)")
		}
		seen[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return false, nil, fmt.Errorf("rbac: visible groups: %w", err)
	}
	ids = make([]int64, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	return false, ids, nil
}
