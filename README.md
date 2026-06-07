# SPARKx509

This is a SPARK/Ada library for parsing X.509 certificates and supporting
certificate validation in SPARKTLS.

## Disclaimer

This project is under active development and should be treated as alpha-quality
software.

## Description

SPARKx509 utilizes a recursive descent parser to parse X509 certificates. It
is designed to fail very early if the certificate is not well-formed, and in
so doing prevent a variety of attacks that can be performed on certificate
parsing libraries. It is also designed to be easy to understand and verify
using formal methods. The parser is currently SPARK verified at the "silver"
level with proven absence of runtime errors (AoRTE).

## Validation Testing

The comprehensive certificate validation tests live in the sibling SPARKTLS
repository, because they exercise full path validation, hostname policy,
trust-store handling, and WebPKI/RFC 5280 behavior beyond the scope of this
parser crate alone.

SPARKx509 is tested against the [x509-limbo](https://x509-limbo.com/) test
suite and compares favorably with other x509/TLS libraries. It currently
passes >99% of the generated & runnable x509-limbo test cases with zero runtime
errors in the test harness run. Several remaining discrepancies are deliberate
policy/scope differences, such as CABF issuer requirements that are not
enforced by a consumer path validator.

## Dependencies

This project depends on `alr` provided by the Alire toolset. You'll want
to use Alire to install a suitable GNAT toolchain.

## Build Instructions

To build the x509 library, run the following command:

```shell
alr build
```

To run the local CI smoke tests:

```shell
tests/smoke/run.sh
```

The active X.509 validation tests are run from the SPARKTLS repository:

```shell
cd ../sparktls
tests/x509/run.sh
```
