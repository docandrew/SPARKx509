#!/usr/bin/env bash
#  Name-constraint regression tests (RFC 5280 4.2.1.10).
#
#  Generates, with openssl, two constrained CAs and a set of leaves,
#  then runs nc_test which parses each pair and checks
#  X509.Satisfies_Name_Constraints against the expected verdict.
#
#    ca_plain: permitted DNS example.com, excluded DNS bad.example.com
#    ca_dot:   permitted DNS .example.com (strict subdomain form)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="${TMPDIR:-/tmp}/sparkx509-nc"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK"

ca() {  # name  nameConstraints-value
  cat > "$1.cnf" <<CNF
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $1
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
nameConstraints = critical,$2
CNF
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
    -days 365 -keyout "$1.key" -out "$1.crt" -config "$1.cnf" >/dev/null 2>&1
  openssl x509 -in "$1.crt" -outform DER -out "$1.der"
}
leaf() {  # name  ca  CN  [SAN list or "-"]
  local name=$1 ca=$2 cn=$3 san=${4:--}
  {
    echo "[req]"; echo "distinguished_name = dn"; echo "prompt = no"
    echo "[dn]"; echo "CN = $cn"
    echo "[ext]"; echo "basicConstraints = critical,CA:FALSE"
    echo "keyUsage = critical,digitalSignature"
    if [ "$san" != "-" ]; then echo "subjectAltName = $san"; fi
  } > "$name.cnf"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
    -keyout "$name.key" -out "$name.csr" -config "$name.cnf" >/dev/null 2>&1
  openssl x509 -req -in "$name.csr" -CA "$ca.crt" -CAkey "$ca.key" -CAcreateserial \
    -days 365 -sha256 -extfile "$name.cnf" -extensions ext -out "$name.crt" >/dev/null 2>&1
  openssl x509 -in "$name.crt" -outform DER -out "$name.der"
}

ca ca_plain "permitted;DNS:example.com,excluded;DNS:bad.example.com"
ca ca_dot   "permitted;DNS:.example.com"

leaf san_ok       ca_plain "san ok"        "DNS:www.example.com"
leaf san_apex     ca_plain "san apex"      "DNS:example.com"
leaf san_bad      ca_plain "san bad"       "DNS:www.other.com"
leaf san_excl     ca_plain "san excluded"  "DNS:bad.example.com"
leaf san_excl_sub ca_plain "san excl sub"  "DNS:x.bad.example.com"
leaf cn_ok        ca_plain "host.example.com"
leaf cn_bad       ca_plain "host.other.com"
leaf cn_excl      ca_plain "bad.example.com"
leaf dot_sub      ca_dot   "dot sub"       "DNS:www.example.com"
leaf dot_apex     ca_dot   "dot apex"      "DNS:example.com"
leaf dot_wild     ca_dot   "dot wild"      "DNS:*.example.com"
leaf dot_other    ca_dot   "dot other"     "DNS:www.other.com"
leaf dot_cn_sub   ca_dot   "host.example.com"
leaf dot_cn_apex  ca_dot   "example.com"

(
  cd "$DIR"
  alr -n --no-tty build
  bin/nc_test "$WORK"
)
