FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
# snmpsim 1.2.2 (BSD-2-Clause) needs pysnmp/pysmi/pyasn1 (BSD-2-Clause) and, for SNMPv3 AES, cryptography
# (Apache-2.0 OR BSD-3-Clause) with cffi/pycparser (MIT/BSD-3-Clause). Test-only image; versions are pinned.
RUN pip install --no-cache-dir snmpsim==1.2.2 pysnmp==7.1.30 pysmi==2.0.0 pyasn1==0.6.4 \
    cryptography==50.0.2 cffi==2.1.1 pycparser==3.0
EXPOSE 161/udp
