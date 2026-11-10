import { describe, expect, it } from "vitest";
import ru from "@/i18n/ru.json";
import { lastErrorKey } from "./lastError";
import { DATA_TABS, parseTabRef, splitTabRef, TABS } from "./tabs";

describe("device tabs", () => {
  it("follow FR-UI-DEV order with Физика first", () => {
    expect(TABS).toEqual(["physical", "config", "cli", "data", "graphs", "backups", "journal", "access", "session"]);
    expect(TABS.map((k) => ru.card.tab[k])).toEqual(["Физика", "Конфиг", "CLI", "Данные", "Графики", "Бэкапы", "Журнал", "Доступ", "Сессия"]);
    expect(DATA_TABS.map((k) => ru.card.tab[k])).toEqual(["Интерфейсы", "ARP", "MAC", "VLAN", "LLDP", "Маршруты", "Компоненты"]);
    expect(splitTabRef(undefined)).toEqual({ tab: "physical", data: "interfaces" });
  });

  it.each([
    ["interfaces", "data/interfaces"],
    ["arp", "data/arp"],
    ["mac", "data/mac"],
    ["vlans", "data/vlans"],
    ["lldp", "data/lldp"],
    ["routes", "data/routes"],
    ["entities", "data/entities"],
    ["profiles", "access"],
    ["problems", "journal"],
  ])("maps the legacy ?tab=%s to %s", (old, ref) => {
    expect(parseTabRef(old)).toBe(ref);
  });

  it("accepts current ids and data refs, rejects anything else", () => {
    expect(parseTabRef("graphs")).toBe("graphs");
    expect(parseTabRef("data/arp")).toBe("data/arp");
    expect(splitTabRef("data/arp")).toEqual({ tab: "data", data: "arp" });
    for (const bad of ["data/x", "toString", "__proto__", "constructor", "", 3, null, undefined]) expect(parseTabRef(bad)).toBeUndefined();
  });
});

describe("last_error", () => {
  it("maps every fixed poller text to its own message", () => {
    const texts = [
      "no usable SNMP credential",
      "snmpv3 profile rejected, using v2c",
      "no SNMP answer during the poll in progress",
      "SNMP request timed out",
      "SNMP authentication failed",
      "poll canceled",
      "SNMP request failed",
      "sysUpTime missing",
    ];
    const keys = texts.map(lastErrorKey);
    expect(new Set(keys).size).toBe(texts.length);
    for (const k of keys) expect(k).not.toBe("lastError.other");
    for (const k of keys) expect(ru.lastError[k.slice("lastError.".length) as keyof typeof ru.lastError]).toBeTruthy();
  });

  it("falls back to the generic message for unknown text", () => {
    expect(lastErrorKey("<b>device said</b>")).toBe("lastError.other");
    expect(lastErrorKey("hasOwnProperty")).toBe("lastError.other");
  });
});
