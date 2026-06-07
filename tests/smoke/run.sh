#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="${TMPDIR:-/tmp}/sparkx509-smoke"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
mkdir -p "$WORK"

KEY="$WORK/localhost.key"
CRT="$WORK/localhost.crt"
DER="$WORK/localhost.der"
CONF="$WORK/openssl.cnf"

cat > "$CONF" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no

[dn]
CN = localhost
O = SPARKx509 Smoke
C = US

[ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days 365 \
  -keyout "$KEY" \
  -out "$CRT" \
  -config "$CONF" >/dev/null 2>&1

openssl x509 -in "$CRT" -outform DER -out "$DER"

(
  cd "$DIR"
  alr -n --no-tty build
  bin/smoke_x509 "$DER"
)
