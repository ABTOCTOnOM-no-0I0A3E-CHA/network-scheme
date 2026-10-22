#!/usr/bin/env python3
"""Test-only event sender for the CI job e2e (never shipped, never run by the application).

Runs inside a container on the devices network and, every few seconds, sends to eventd
a UDP syslog message, a TCP syslog message (LF framing) and, with a community, an
SNMPv2c linkDown trap. The source address is the container's own address: that is the
identity eventd checks. The trap is encoded by hand (BER), so the script needs only the
Python standard library.

usage: send_events.py TARGET_IP MARKER [COMMUNITY]
  MARKER     one word (letters, digits) that ends up in the message text
  COMMUNITY  when given, a linkDown trap is sent as well
"""
import socket
import sys
import time


def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + ln + body


def integer(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(0x02, v.to_bytes(n, "big", signed=True))


def oid(dotted):
    a = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * a[0] + a[1]])
    for sub in a[2:]:
        chunk = [sub & 0x7F]
        sub >>= 7
        while sub:
            chunk.append(0x80 | (sub & 0x7F))
            sub >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def varbind(name, value):
    return tlv(0x30, oid(name) + value)


def link_down_trap(community, request_id):
    """SNMPv2c trap: sysUpTime.0, snmpTrapOID.0 = linkDown, ifIndex.1 = 1."""
    vbs = (
        varbind("1.3.6.1.2.1.1.3.0", tlv(0x43, (123456).to_bytes(3, "big")))  # TimeTicks
        + varbind("1.3.6.1.6.3.1.1.4.1.0", oid("1.3.6.1.6.3.1.1.5.3"))
        + varbind("1.3.6.1.2.1.2.2.1.1.1", integer(1))
    )
    pdu = tlv(0xA7, integer(request_id) + integer(0) + integer(0) + tlv(0x30, vbs))
    return tlv(0x30, integer(1) + tlv(0x04, community.encode()) + pdu)


def main():
    target, marker = sys.argv[1], sys.argv[2]
    community = sys.argv[3] if len(sys.argv) > 3 else ""
    n = 0
    while True:
        n += 1
        text = "<14>%s e2ehost e2eapp: %s%s" % (time.strftime("%b %e %H:%M:%S"), marker, "udp")
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.sendto(text.encode(), (target, 1514))
        if community:
            udp.sendto(link_down_trap(community, n), (target, 1162))
        udp.close()
        try:
            with socket.create_connection((target, 1514), timeout=3) as tcp:
                tcp.sendall(("<14>%s e2ehost e2eapp: %stcp\n" % (time.strftime("%b %e %H:%M:%S"), marker)).encode())
        except OSError as e:
            print("tcp syslog:", e, flush=True)
        time.sleep(3)


if __name__ == "__main__":
    main()
