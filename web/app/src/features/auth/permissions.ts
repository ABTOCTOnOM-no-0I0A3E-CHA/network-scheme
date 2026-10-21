import type { Session } from "./useSession";

/**
 * UI hint only: devices.manage belongs to the admin role (global or on a group).
 * The API stays the source of truth and answers 403/404 where the scope differs.
 */
export function canManageDevices(session: Session | null | undefined): boolean {
  return !!session?.roles.some((r) => r.role === "admin");
}

/** UI hint only: devices.poll belongs to the operator and admin roles. */
export function canPollDevices(session: Session | null | undefined): boolean {
  return !!session?.roles.some((r) => r.role === "operator" || r.role === "admin");
}
