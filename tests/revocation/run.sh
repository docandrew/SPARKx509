#!/usr/bin/env bash
# Build and run the CRL / OCSP parser smoke test against gen.sh fixtures.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="${TMPDIR:-/tmp}/sparkx509-revocation"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
bash "$DIR/gen.sh" "$WORK" >/dev/null
(
  cd "$DIR"
  alr -n --no-tty build
  bin/smoke_revocation "$WORK"
)
