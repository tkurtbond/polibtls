#!/bin/sh
# cert-info.sh CRT: what libtls should report of the certificate in file
# CRT, by openssl, a line each: its hash as tls_peer_cert_hash gives it
# ("SHA256:" and lowercase hex of the DER), its subject and issuer in
# X509_NAME_oneline's form (openssl's -nameopt compat), and the start
# and end of its validity in seconds since the epoch. For TestInfo.
set -e
c=$1
printf 'SHA256:%s\n' "$(openssl x509 -in "$c" -outform der | sha256sum | cut -d' ' -f1)"
openssl x509 -in "$c" -noout -subject -nameopt compat | sed 's/^subject=//'
openssl x509 -in "$c" -noout -issuer -nameopt compat | sed 's/^issuer=//'
date -d "$(openssl x509 -in "$c" -noout -startdate | cut -d= -f2)" +%s
date -d "$(openssl x509 -in "$c" -noout -enddate | cut -d= -f2)" +%s
