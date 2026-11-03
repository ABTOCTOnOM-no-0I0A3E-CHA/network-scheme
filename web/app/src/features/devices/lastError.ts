/*
 * The poller stores a fixed English text as a device's last_error (internal/poller/availability.go). Known texts map to
 * i18n keys; anything else (a newer poller, an older row) gets the generic key, so raw server text never reaches the UI.
 */
const KNOWN: Record<string, string> = {
  "no usable SNMP credential": "noProfile",
  "snmpv3 profile rejected, using v2c": "v2Fallback",
  "no SNMP answer during the poll in progress": "busyNoAnswer",
  "SNMP request timed out": "timeout",
  "SNMP authentication failed": "authFailed",
  "poll canceled": "canceled",
  "SNMP request failed": "snmpFailed",
  "sysUpTime missing": "noUpTime",
};

/** The i18n key of a last_error text: lastError.<known> or lastError.other. */
export function lastErrorKey(text: string): string {
  return `lastError.${Object.hasOwn(KNOWN, text) ? KNOWN[text] : "other"}`;
}
