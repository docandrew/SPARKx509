# SPARKx509 CI

`ci/check.sh` is the local wrapper for the reproducible hosted-CI lane. Hosted
CI runs the same core command directly:

```shell
nix develop --command alr build
```

The local `ci/check.sh` wrapper also runs `tests/smoke/run.sh`, which builds
a tiny test crate and parses a generated localhost DER certificate.

The broad x509-limbo validation suite is exercised from the sibling SPARKTLS
repository, where path validation and WebPKI policy are tested end to end.
Formal proof is intentionally not part of default CI because `gnatprove` runs
are long and sensitive to prover/toolchain differences.
