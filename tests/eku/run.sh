#!/usr/bin/env bash
#  Extended key usage regression tests (RFC 5280 4.2.1.12).
#
#  Generates, with openssl, P-384 certificates carrying different EKU
#  sets, then runs eku_test which parses each one and checks the EKU
#  getters and X509.Issuer_EKU_Allows_Signing for every purpose.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="${TMPDIR:-/tmp}/sparkx509-eku"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK"

cert() {  # name  CA:TRUE|CA:FALSE  extendedKeyUsage-value or "-"
  local name=$1 bc=$2 eku=$3 ku
  if [ "$bc" = "CA:TRUE" ]; then
    ku="keyCertSign,cRLSign"
  else
    ku="digitalSignature"
  fi
  {
    echo "[req]"; echo "distinguished_name = dn"; echo "x509_extensions = ext"
    echo "prompt = no"
    echo "[dn]"; echo "CN = $name"
    echo "[ext]"; echo "basicConstraints = critical,$bc"
    echo "keyUsage = critical,$ku"
    echo "subjectKeyIdentifier = hash"
    if [ "$eku" != "-" ]; then echo "extendedKeyUsage = $eku"; fi
  } > "$name.cnf"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -sha384 -nodes \
    -days 365 -keyout "$name.key" -out "$name.crt" -config "$name.cnf" \
    >/dev/null 2>&1
  openssl x509 -in "$name.crt" -outform DER -out "$name.der"
}

cert leaf_code        CA:FALSE codeSigning
cert leaf_code_crit   CA:FALSE critical,codeSigning
cert leaf_server      CA:FALSE serverAuth
cert leaf_mixed       CA:FALSE serverAuth,codeSigning,clientAuth
cert leaf_ocsp        CA:FALSE OCSPSigning
cert leaf_timestamp   CA:FALSE timeStamping
cert leaf_any         CA:FALSE anyExtendedKeyUsage
cert leaf_none        CA:FALSE -
cert ca_code          CA:TRUE  codeSigning
cert ca_server        CA:TRUE  serverAuth,clientAuth
cert ca_any           CA:TRUE  anyExtendedKeyUsage
cert ca_none          CA:TRUE  -

(
  cd "$DIR"
  alr -n --no-tty build
  bin/eku_test "$WORK"
)
