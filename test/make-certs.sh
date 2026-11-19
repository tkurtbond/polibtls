#!/bin/sh
# make-certs.sh DIR: make the tests' certificates and keys in DIR, each
# in two kinds, ECDSA P-256 (-ec) and RSA 2048 (-rsa), since Gemini
# clients and servers meet both (PLAN.md, "Testing"):
#
#   ca-K        a CA, which signs server-K
#   server-K    localhost, 127.0.0.1 and ::1, signed by ca-K: for a
#               client that verifies the server
#   self-K      localhost, self-signed, as most Gemini servers' are
#   other-K     other.example, self-signed: a second name for SNI
#   client1-K   two self-signed client certificates, as Gemini clients
#   client2-K   make them
#   expired-K   self-signed, valid only in January 2020
#   renewed-K   self-K renewed: localhost, self-signed by self-K's key,
#               so its key's hash is self-K's and its own differs; it
#               ends after 2049, so that its notAfter is a
#               GeneralizedTime, not a UTCTime (RFC 5280, 4.1.2.5)
#
# Each pair is NAME.crt and NAME.key, but for renewed-K, whose key is
# self-K.key. They are made afresh by every build from clean and never
# committed: a private key in a repository, even a test one, gets copied
# into real use. The keys are made unreadable to others, and nothing
# here prints one.
#
# It runs with OpenSSL 3 (Linux, FreeBSD, NetBSD) and OpenBSD's LibreSSL
# alike, so it uses only what both have (PLAN.md, Phase 10): its own
# configuration, not the system's, whose default extensions differ; the
# server's certificate signed by x509 -req (req -CA is OpenSSL 3's), and
# the expired one made by ca -startdate/-enddate (req -not_before is
# OpenSSL 3's). The digest is named everywhere: LibreSSL's x509 -req
# signs with SHA-1 by default, which GnuTLS rejects as insecure.
set -e
dir=$1
[ -n "$dir" ] || { echo "usage: $0 DIR" >&2; exit 2; }
mkdir -p "$dir"
cd "$dir"
umask 077

days=3650
cnf=certs.cnf
cat > $cnf <<'EOF'
[req]
distinguished_name = dn
[dn]
[x_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[x_local]
basicConstraints = critical,CA:FALSE
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1
[x_other]
basicConstraints = critical,CA:FALSE
subjectAltName = DNS:other.example
[x_leaf]
basicConstraints = critical,CA:FALSE
# for ca, which makes the expired certificate
[ca]
default_ca = ca_expired
[ca_expired]
database = ca.db/index.txt
new_certs_dir = ca.db
serial = ca.db/serial
default_md = sha256
policy = ca_policy
unique_subject = no
[ca_policy]
commonName = supplied
EOF

# genpkey says nothing useful on standard error (OpenSSL 3 has -quiet
# for it, LibreSSL hasn't), but a failure stops the script.
key() { # key NAME KIND
  case $2 in
  ec) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -pkeyopt ec_param_enc:named_curve -out "$1.key" 2>/dev/null ;;
  rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
         -out "$1.key" 2>/dev/null ;;
  esac
}

self() { # self NAME SUBJECT EXTENSIONS: a self-signed certificate
  openssl req -config $cnf -new -x509 -sha256 -key "$1.key" -out "$1.crt" \
    -days $days -subj "$2" -extensions "$3"
}

serial=1
for k in ec rsa; do
  key ca-$k $k
  self ca-$k "/CN=polibtls test CA ($k)" x_ca

  key server-$k $k
  openssl req -config $cnf -new -sha256 -key server-$k.key -subj /CN=localhost \
    -out server-$k.csr
  openssl x509 -req -in server-$k.csr -CA ca-$k.crt -CAkey ca-$k.key -sha256 \
    -set_serial $serial -days $days -extfile $cnf -extensions x_local \
    -out server-$k.crt 2>/dev/null
  serial=$((serial + 1))

  key self-$k $k
  self self-$k /CN=localhost x_local

  openssl req -config $cnf -new -x509 -sha256 -key self-$k.key -out renewed-$k.crt \
    -days 10000 -subj /CN=localhost -extensions x_local

  key other-$k $k
  self other-$k /CN=other.example x_other

  for c in client1 client2; do
    key $c-$k $k
    self $c-$k "/CN=polibtls test $c" x_leaf
  done

  key expired-$k $k
  rm -rf ca.db; mkdir ca.db; : > ca.db/index.txt; echo 01 > ca.db/serial
  openssl req -config $cnf -new -sha256 -key expired-$k.key \
    -subj "/CN=polibtls test expired" -out expired-$k.csr
  openssl ca -config $cnf -batch -notext -selfsign -keyfile expired-$k.key \
    -in expired-$k.csr -out expired-$k.crt -extfile $cnf -extensions x_leaf \
    -startdate 20200101000000Z -enddate 20200201000000Z 2>/dev/null

  # Check what the tests will rely on: the CA verifies its server, and
  # the expired one has expired (x509 -checkend 0 fails on it).
  openssl verify -CAfile ca-$k.crt server-$k.crt > /dev/null
  if openssl x509 -in expired-$k.crt -noout -checkend 0 > /dev/null; then
    echo "$0: expired-$k.crt has not expired" >&2; exit 1
  fi
done
rm -rf ca.db ./*.csr $cnf
for c in ./*.crt; do
  if ! openssl x509 -in "$c" -noout -text |
       grep -i 'Signature Algorithm: .*sha256' > /dev/null; then
    echo "$0: $c is not signed with SHA-256" >&2; exit 1
  fi
done
# The certificates are public; only the keys need hiding.
chmod 644 ./*.crt
