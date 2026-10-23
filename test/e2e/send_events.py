#!/usr/bin/env python3
"""Test-only event sender for the CI job e2e (never shipped, never run by the application).

Runs inside a container on the devices network and, every few seconds, sends to eventd
a UDP syslog message, a TCP syslog message (LF framing) and, with a community, an
SNMPv2c linkDown trap. The source address is the container's own address: that is the
identity eventd checks. The trap is encoded by hand (BER), so the script needs only the
Python standard library.

usage: send_events.py TARGET_IP MARKER [COMMUNITY [CAFILE TLS_NAME]]
  MARKER     one word (letters, digits) that ends up in the message text
  COMMUNITY  when given (not "-"), a linkDown trap is sent as well
  CAFILE     when given, one message per round goes over TLS (port 6514), verified against this CA
             for the host name TLS_NAME

With the environment variable TRAP_CONTROL (a file path) the trap is chosen by the file instead: every round sends the
trap it names (linkDown or linkUp, for ifIndex TRAP_IFINDEX, default 1) or none while the file is missing or empty, so a
test can open and close a link problem of this source on demand. Without it a linkDown for ifIndex 1 is sent every round.

Ports default to the container ports of eventd (1514 syslog, 1162 traps, 6514 TLS); the environment
variables SYSLOG_PORT, TRAP_PORT and TLS_PORT replace them, e.g. 514 for the published port.
"""
import os
import socket
import ssl
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


LINK_TRAPS = {"linkDown": "1.3.6.1.6.3.1.1.5.3", "linkUp": "1.3.6.1.6.3.1.1.5.4"}


def link_trap(community, request_id, name="linkDown", if_index=1):
    """SNMPv2c trap: sysUpTime.0, snmpTrapOID.0 = linkDown or linkUp, ifIndex.N = N."""
    vbs = (
        varbind("1.3.6.1.2.1.1.3.0", tlv(0x43, (123456).to_bytes(3, "big")))  # TimeTicks
        + varbind("1.3.6.1.6.3.1.1.4.1.0", oid(LINK_TRAPS[name]))
        + varbind("1.3.6.1.2.1.2.2.1.1.%d" % if_index, integer(if_index))
    )
    pdu = tlv(0xA7, integer(request_id) + integer(0) + integer(0) + tlv(0x30, vbs))
    return tlv(0x30, integer(1) + tlv(0x04, community.encode()) + pdu)


def read_control(path):
    """The trap named in the control file (linkDown or linkUp); none when the file is missing, empty or names anything else."""
    try:
        with open(path) as f:
            name = f.read().strip()
    except OSError:
        return ""
    return name if name in LINK_TRAPS else ""


def main():
    target, marker = sys.argv[1], sys.argv[2]
    community = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" else ""
    cafile, tls_name = (sys.argv[4], sys.argv[5]) if len(sys.argv) > 5 else ("", "")
    syslog_port = int(os.environ.get("SYSLOG_PORT", "1514"))
    trap_port = int(os.environ.get("TRAP_PORT", "1162"))
    tls_port = int(os.environ.get("TLS_PORT", "6514"))
    control = os.environ.get("TRAP_CONTROL", "")
    if_index = int(os.environ.get("TRAP_IFINDEX", "1"))
    ctx = ssl.create_default_context(cafile=cafile) if cafile else None
    n = 0
    while True:
        n += 1
        text = "<14>%s e2ehost e2eapp: %s%s" % (time.strftime("%b %e %H:%M:%S"), marker, "udp")
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.sendto(text.encode(), (target, syslog_port))
        if community and control:
            name = read_control(control)
            if name:
                udp.sendto(link_trap(community, n, name, if_index), (target, trap_port))
        elif community:
            udp.sendto(link_trap(community, n), (target, trap_port))
        udp.close()
        try:
            with socket.create_connection((target, syslog_port), timeout=3) as tcp:
                tcp.sendall(("<14>%s e2ehost e2eapp: %stcp\n" % (time.strftime("%b %e %H:%M:%S"), marker)).encode())
        except OSError as e:
            print("tcp syslog:", e, flush=True)
        if ctx:
            try:
                with socket.create_connection((target, tls_port), timeout=3) as raw:
                    with ctx.wrap_socket(raw, server_hostname=tls_name) as tls:
                        tls.sendall(("<14>%s e2ehost e2eapp: %stls\n" % (time.strftime("%b %e %H:%M:%S"), marker)).encode())
            except (OSError, ssl.SSLError) as e:
                print("tls syslog:", e, flush=True)
        time.sleep(3)


if __name__ == "__main__":
    main()
