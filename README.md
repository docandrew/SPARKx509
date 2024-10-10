# SPARKx509

This is a prototype for performing X509 certificate parsing using SPARK/Ada.

## Disclaimer

This project is in its VERY early stages and is not suitable for any
kind of production use. It may be useful for research purposes or inspiration.

## Description

SPARKx509 utilizes a recursive descent parser to parse X509 certificates. It
is designed to fail very early if the certificate is not well-formed, and in
so doing prevent a variety of attacks that can be performed on certificate
parsing libraries. It is also designed to be easy to understand and verify
using formal methods.

## Dependencies

This project depends on `alr` provided by the Alire toolset. You'll want
to use Alire to install a suitable GNAT toolchain.

## Build Instructions

To build the x509 library, run the following command:

```shell
alr build
```

To build the tests, run the following commands:

```shell
cd tests/
./build_tests.sh
```
