#!/bin/sh
# cert-info.sh CRT: what libtls should report of the certificate in file
# CRT, by openssl, a line each: its hash as tls_peer_cert_hash gives it
# ("SHA256:" and lowercase hex of the DER), its subject and issuer in
# X509_NAME_oneline's form (openssl's -nameopt compat), and the start
# and end of its validity in seconds since the epoch, and the hash of
# its public key as TlsCerts.KeyHash gives it ("SHA256:" and lowercase
# hex of the SubjectPublicKeyInfo's DER). For TestInfo and TestCerts.
#
# Portable to the BSDs and to OpenBSD's LibreSSL (PLAN.md, Phase 10): no
# sha256sum or date -d, which differ or are missing there, so the hash
# is openssl's fingerprint and the times are converted by awk; LibreSSL
# prints "subject= /CN=...", with a space; dgst prints "SHA2-256(stdin)= "
# before the hash in OpenSSL 3, "(stdin)= " or nothing elsewhere.
set -e
c=$1
openssl x509 -in "$c" -noout -fingerprint -sha256 |
  sed 's/^[^=]*=//; s/://g' | tr 'A-F' 'a-f' | sed 's/^/SHA256:/'
openssl x509 -in "$c" -noout -subject -nameopt compat | sed 's/^subject= *//'
openssl x509 -in "$c" -noout -issuer -nameopt compat | sed 's/^issuer= *//'
# notBefore=Jan  1 00:00:00 2020 GMT: days since the epoch by the civil
# calendar (Howard Hinnant's days_from_civil), then seconds.
openssl x509 -in "$c" -noout -startdate -enddate | sed 's/^[^=]*=//' |
awk '{
  m = (index("JanFebMarAprMayJunJulAugSepOctNovDec", $1) + 2) / 3
  d = $2; y = $4; split($3, t, ":")
  if (m <= 2) y--
  era = int(y / 400); yoe = y - era * 400
  doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
  doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
  days = era * 146097 + doe - 719468
  printf "%.0f\n", ((days * 24 + t[1]) * 60 + t[2]) * 60 + t[3]
}'
openssl x509 -in "$c" -noout -pubkey | openssl pkey -pubin -outform DER |
  openssl dgst -sha256 | awk '{ print "SHA256:" tolower($NF) }'
