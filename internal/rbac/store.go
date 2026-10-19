package rbac

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

/* Store errors. */
var (
	ErrLastAdmin     = errors.New("rbac: would remove the last global admin")
	ErrGroupCycle    = errors.New("rbac: group hierarchy cycle")
	ErrGroupNotFound = errors.New("rbac: group not found")
	ErrGroupExists   = errors.New("rbac: group name already used under this parent")
	ErrGroupNotEmpty = errors.New("rbac: group has child groups")
	ErrUserNotFound  = errors.New("rbac: user not found")
	ErrInvalidRole   = errors.New("rbac: invalid role")
)

/* Transaction-scoped advisory lock keys serialising hierarchy and admin changes. */
const (
	lockGroups   int64 = 0x6e6d7301
	lockBindings int64 = 0x6e6d7302
)

// Group is a node of the device group tree.
type Group struct {
	ID       int64
	ParentID *int64
	Name     string
}

/*
Store persists groups and role bindings. State-changing methods run in the
caller's transaction so the caller can audit the change atomically; reads use
the pool.
*/
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store over pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// LoadSubject loads the role bindings of userID.
func (s *Store) LoadSubject(ctx context.Context, userID int64) (Subject, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT role, group_id FROM core.role_binding WHERE user_id = $1 ORDER BY role, group_id NULLS FIRST`, userID)
	if err != nil {
		return Subject{}, fmt.Errorf("rbac: load bindings: %w", err)
	}
	bs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Binding, error) {
		var b Binding
		err := r.Scan(&b.Role, &b.GroupID)
		return b, err
	})
	if err != nil {
		return Subject{}, fmt.Errorf("rbac: load bindings: %w", err)
	}
	return Subject{UserID: userID, Bindings: bs}, nil
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func ancestors(ctx context.Context, q querier, groupID int64) ([]int64, error) {
	rows, err := q.Query(ctx, `
		WITH RECURSIVE up(id, parent_id, depth) AS (
			SELECT id, parent_id, 0 FROM core.device_group WHERE id = $1
			UNION ALL
			SELECT g.id, g.parent_id, up.depth + 1 FROM core.device_group g JOIN up ON g.id = up.parent_id
		)
		SELECT id FROM up WHERE depth > 0 ORDER BY depth`, groupID)
	if err != nil {
		return nil, fmt.Errorf("rbac: ancestors: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

/*
Ancestors returns the parent chain of groupID, nearest first, excluding the
group itself. The hierarchy is acyclic, so the recursion terminates.
*/
func (s *Store) Ancestors(ctx context.Context, groupID int64) ([]int64, error) {
	return ancestors(ctx, s.pool, groupID)
}

// ListGroups returns all groups ordered by id.
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, parent_id, name FROM core.device_group ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("rbac: list groups: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Group, error) {
		var g Group
		err := r.Scan(&g.ID, &g.ParentID, &g.Name)
		return g, err
	})
}

// CreateGroup adds a group under parent (nil for a root) and returns its id.
func (s *Store) CreateGroup(ctx context.Context, tx pgx.Tx, parent *int64, name string) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx,
		`INSERT INTO core.device_group (parent_id, name) VALUES ($1, $2) RETURNING id`, parent, name).Scan(&id)
	if err != nil {
		return 0, groupErr(err)
	}
	return id, nil
}

func groupErr(err error) error {
	switch pgCode(err) {
	case "23505":
		return ErrGroupExists
	case "23503":
		return ErrGroupNotFound
	}
	return fmt.Errorf("rbac: group: %w", err)
}

// RenameGroup changes the name of group id.
func (s *Store) RenameGroup(ctx context.Context, tx pgx.Tx, id int64, name string) error {
	tag, err := tx.Exec(ctx, `UPDATE core.device_group SET name = $2 WHERE id = $1`, id, name)
	if err != nil {
		return groupErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return nil
}

/*
MoveGroup reparents group id under newParent (nil for a root). A move that
would put a group below itself or one of its descendants returns
ErrGroupCycle; hierarchy changes are serialised so concurrent moves cannot
jointly create a cycle.
*/
func (s *Store) MoveGroup(ctx context.Context, tx pgx.Tx, id int64, newParent *int64) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockGroups); err != nil {
		return fmt.Errorf("rbac: lock groups: %w", err)
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.device_group WHERE id = $1)`, id).Scan(&exists); err != nil {
		return fmt.Errorf("rbac: move group: %w", err)
	}
	if !exists {
		return ErrGroupNotFound
	}
	if newParent != nil {
		if *newParent == id {
			return ErrGroupCycle
		}
		anc, err := ancestors(ctx, tx, *newParent)
		if err != nil {
			return err
		}
		for _, a := range anc {
			if a == id {
				return ErrGroupCycle
			}
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE core.device_group SET parent_id = $2 WHERE id = $1`, id, newParent); err != nil {
		return groupErr(err)
	}
	return nil
}

/*
DeleteGroup removes a leaf group together with the role bindings scoped to it.
A group with children returns ErrGroupNotEmpty.
*/
func (s *Store) DeleteGroup(ctx context.Context, tx pgx.Tx, id int64) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockGroups); err != nil {
		return fmt.Errorf("rbac: lock groups: %w", err)
	}
	tag, err := tx.Exec(ctx, `DELETE FROM core.device_group WHERE id = $1`, id)
	if pgCode(err) == "23503" {
		return ErrGroupNotEmpty
	}
	if err != nil {
		return fmt.Errorf("rbac: delete group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return nil
}

/*
SetBindings replaces all bindings of userID. If the user currently holds a
global admin binding that the new set drops and no other enabled user holds
one, it returns ErrLastAdmin. The check is serialised by an advisory lock held
until the caller's transaction ends, so two concurrent calls cannot remove the
last two admins.
*/
func (s *Store) SetBindings(ctx context.Context, tx pgx.Tx, userID int64, bindings []Binding) error {
	keepsAdmin := false
	for _, b := range bindings {
		if !b.Role.Valid() {
			return ErrInvalidRole
		}
		if b.Role == RoleAdmin && b.GroupID == nil {
			keepsAdmin = true
		}
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockBindings); err != nil {
		return fmt.Errorf("rbac: lock bindings: %w", err)
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core."user" WHERE id = $1)`, userID).Scan(&exists); err != nil {
		return fmt.Errorf("rbac: set bindings: %w", err)
	}
	if !exists {
		return ErrUserNotFound
	}
	if !keepsAdmin {
		var wasAdmin, others bool
		err := tx.QueryRow(ctx, `
			SELECT
			  EXISTS (SELECT 1 FROM core.role_binding WHERE user_id = $1 AND role = 'admin' AND group_id IS NULL),
			  EXISTS (SELECT 1 FROM core.role_binding rb JOIN core."user" u ON u.id = rb.user_id
			          WHERE rb.user_id <> $1 AND rb.role = 'admin' AND rb.group_id IS NULL AND NOT u.disabled)`,
			userID).Scan(&wasAdmin, &others)
		if err != nil {
			return fmt.Errorf("rbac: admin check: %w", err)
		}
		if wasAdmin && !others {
			return ErrLastAdmin
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.role_binding WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("rbac: clear bindings: %w", err)
	}
	for _, b := range bindings {
		_, err := tx.Exec(ctx,
			`INSERT INTO core.role_binding (user_id, role, group_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			userID, string(b.Role), b.GroupID)
		if pgCode(err) == "23503" {
			return ErrGroupNotFound
		}
		if err != nil {
			return fmt.Errorf("rbac: insert binding: %w", err)
		}
	}
	return nil
}
