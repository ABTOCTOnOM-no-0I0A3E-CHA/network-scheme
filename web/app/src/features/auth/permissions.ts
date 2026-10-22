import type { Session } from "./useSession";

/**
 * UI hint only: devices.manage belongs to the admin role (global or on a group).
 * The API stays the source of truth and answers 403/404 where the scope differs.
 */
export function canManageDevices(session: Session | null | undefined): boolean {
  return !!session?.roles.some((r) => r.role === "admin");
}

/**
 * UI hint only: groups.manage (listing groups) belongs to the admin role bound globally;
 * an admin on a single group gets 403 from /api/groups.
 */
export function canListGroups(session: Session | null | undefined): boolean {
  return !!session?.roles.some((r) => r.role === "admin" && r.group_id === null);
}

/** UI hint only: devices.poll belongs to the operator and admin roles. */
export function canPollDevices(session: Session | null | undefined): boolean {
  return !!session?.roles.some((r) => r.role === "operator" || r.role === "admin");
}

/** UI hint only: events.manage (trap rules) is not group-scoped, so only a global admin binding holds it. */
export function canManageEvents(session: Session | null | undefined): boolean {
  return !!session?.roles.some((r) => r.role === "admin" && r.group_id === null);
}

/** UI hint only: system.read is not group-scoped, so only a global admin or operator binding holds it. */
export function canReadSystem(session: Session | null | undefined): boolean {
  return !!session?.roles.some((r) => (r.role === "operator" || r.role === "admin") && r.group_id === null);
}
