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
#
# Each pair is NAME.crt and NAME.key. They are made afresh by every build
# from clean and never committed: a private key in a repository, even a
# test one, gets copied into real use. The keys are made unreadable to
# others, and nothing here prints one.
#
# openssl 3's req -x509 adds the CA extensions of its configuration to a
# certificate unless told otherwise, so each leaf says CA:FALSE.
set -e
dir=$1
[ -n "$dir" ] || { echo "usage: $0 DIR" >&2; exit 2; }
mkdir -p "$dir"
cd "$dir"
umask 077

days=3650
leaf='-addext basicConstraints=critical,CA:FALSE'

key() { # key NAME KIND
  case $2 in
  ec) openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" ;;
  rsa) openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" ;;
  esac
}

for k in ec rsa; do
  key ca-$k $k
  openssl req -new -x509 -key ca-$k.key -out ca-$k.crt -days $days \
    -subj "/CN=polibtls test CA ($k)" \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign

  # With -CA, req signs with -CAkey and takes -key as the subject's key;
  # it says so on standard error, which is expected.
  key server-$k $k
  openssl req -new -x509 -key server-$k.key -CA ca-$k.crt -CAkey ca-$k.key \
    -out server-$k.crt -days $days -subj /CN=localhost $leaf \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1' 2>/dev/null

  key self-$k $k
  openssl req -new -x509 -key self-$k.key -out self-$k.crt -days $days \
    -subj /CN=localhost $leaf \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'

  key other-$k $k
  openssl req -new -x509 -key other-$k.key -out other-$k.crt -days $days \
    -subj /CN=other.example $leaf -addext subjectAltName=DNS:other.example

  for c in client1 client2; do
    key $c-$k $k
    openssl req -new -x509 -key $c-$k.key -out $c-$k.crt -days $days \
      -subj "/CN=polibtls test $c" $leaf
  done

  key expired-$k $k
  openssl req -new -x509 -key expired-$k.key -out expired-$k.crt \
    -not_before 20200101000000Z -not_after 20200201000000Z \
    -subj "/CN=polibtls test expired" $leaf

  # Check what the tests will rely on: the CA verifies its server, and
  # the expired one has expired (x509 -checkend 0 fails on it).
  openssl verify -CAfile ca-$k.crt server-$k.crt > /dev/null
  if openssl x509 -in expired-$k.crt -noout -checkend 0 > /dev/null; then
    echo "$0: expired-$k.crt has not expired" >&2; exit 1
  fi
done
# The certificates are public; only the keys need hiding.
chmod 644 ./*.crt
