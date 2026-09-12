#!/usr/bin/env bash
# Generate CRL / OCSP fixtures for tests/revocation/smoke_revocation.
# Output DER files land in $1 (default: ${TMPDIR:-/tmp}/sparkx509-revocation).
set -euo pipefail
OUT="${1:-${TMPDIR:-/tmp}/sparkx509-revocation}"
rm -rf "$OUT"; mkdir -p "$OUT/ca"; cd "$OUT"
GEN_EPOCH=$(date -u +%s)   # stamped before any openssl "now"; the test clock is derived from it
export OPENSSL_CONF=/dev/null

cat > ca.cnf <<'CNF'
[ ca ]
default_ca = test_ca
[ test_ca ]
dir = ./ca
database = $dir/index.txt
new_certs_dir = $dir
serial = $dir/serial
crlnumber = $dir/crlnumber
certificate = ca.crt
private_key = ca.key
default_md = sha256
default_days = 365
default_crl_days = 7
policy = any_pol
crl_extensions = crl_ext
copy_extensions = copy
unique_subject = no
[ any_pol ]
commonName = supplied
[ crl_ext ]
authorityKeyIdentifier = keyid:always
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = placeholder
[ ext_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ ext_leaf ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:leaf.test,DNS:localhost
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ ext_leaf_staple ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:staple.test,DNS:localhost
tlsfeature = status_request
[ ext_ocsp ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,OCSPSigning
noCheck = ignored
# Sharded CRLs (RFC 5280 5.2.5 issuingDistributionPoint): leaves point
# at shard 1 or shard 2; each shard CRL is scoped to its own URI.
[ ext_leaf_shard1 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:shard1.test,DNS:localhost
crlDistributionPoints = URI:http://crl.test/shard1.crl
[ ext_leaf_shard2 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:shard2.test,DNS:localhost
crlDistributionPoints = URI:http://crl.test/shard2.crl
[ crl_ext_shard1 ]
authorityKeyIdentifier = keyid:always
issuingDistributionPoint = critical,@idp_shard1
[ idp_shard1 ]
fullname = URI:http://crl.test/shard1.crl
[ crl_ext_shard2 ]
authorityKeyIdentifier = keyid:always
issuingDistributionPoint = critical,@idp_shard2
[ idp_shard2 ]
fullname = URI:http://crl.test/shard2.crl
CNF
touch ca/index.txt; echo 1000 > ca/serial; echo 01 > ca/crlnumber

q() { "$@" >>gen.log 2>&1 || { echo "FAILED: $*"; tail -5 gen.log; exit 1; }; }
# CA (RSA) and an EC CA for algorithm coverage
q openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 -keyout ca.key -out ca.crt \
  -config ca.cnf -subj "/CN=SPARKx509 Test CA/O=SPARKx509" -extensions ext_ca
# Leaves
for n in good revoked; do
  q openssl req -newkey rsa:2048 -nodes -keyout $n.key -out $n.csr -config ca.cnf -subj "/CN=$n.test"
  q openssl ca -batch -config ca.cnf -extensions ext_leaf -in $n.csr -out $n.crt -notext
done
q openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout staple.key -out staple.csr \
  -config ca.cnf -subj "/CN=staple.test"
q openssl ca -batch -config ca.cnf -extensions ext_leaf_staple -in staple.csr -out staple.crt -notext
# Delegated OCSP responder
q openssl req -newkey rsa:2048 -nodes -keyout ocsp.key -out ocsp.csr -config ca.cnf -subj "/CN=OCSP Responder"
q openssl ca -batch -config ca.cnf -extensions ext_ocsp -in ocsp.csr -out ocsp.crt -notext
# Revoke one leaf with a reason, then issue the CRL
q openssl ca -batch -config ca.cnf -revoke revoked.crt -crl_reason keyCompromise
q openssl ca -batch -config ca.cnf -gencrl -out crl.pem
openssl crl -in crl.pem -outform DER -out crl.der
# Sharded CRLs: a leaf per shard, both revoked, each shard listing only
# its own leaf (separate CA databases so the shards differ).
for n in 1 2; do
  q openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout shard$n.key -out shard$n.csr \
    -config ca.cnf -subj "/CN=shard$n.test"
  q openssl ca -batch -config ca.cnf -extensions ext_leaf_shard$n -in shard$n.csr -out shard$n.crt -notext
done
for n in 1 2; do
  mkdir -p shardca$n; cp ca/index.txt shardca$n/index.txt; echo 0$n > shardca$n/crlnumber
  sed "s#dir = ./ca\$#dir = ./shardca$n#; s#^crl_extensions = crl_ext\$#crl_extensions = crl_ext_shard$n#" ca.cnf > shardca$n.cnf
  q openssl ca -batch -config shardca$n.cnf -revoke shard$n.crt -crl_reason superseded
  q openssl ca -batch -config shardca$n.cnf -gencrl -out crl_shard$n.pem
  openssl crl -in crl_shard$n.pem -outform DER -out crl_shard$n.der
done
# An empty CRL (no revokedCertificates) from a fresh index
mkdir -p ca2; touch ca2/index.txt; echo 01 > ca2/crlnumber
sed 's#dir = ./ca$#dir = ./ca2#' ca.cnf > ca2.cnf
q openssl ca -batch -config ca2.cnf -gencrl -out crl_empty.pem
openssl crl -in crl_empty.pem -outform DER -out crl_empty.der
# OCSP: request per leaf, responses signed by the CA and by the delegate
for n in good revoked; do
  q openssl ocsp -issuer ca.crt -cert $n.crt -no_nonce -reqout req_$n.der
  q openssl ocsp -index ca/index.txt -CA ca.crt -rsigner ca.crt -rkey ca.key \
    -reqin req_$n.der -respout ocsp_${n}_ca.der -ndays 7
  q openssl ocsp -index ca/index.txt -CA ca.crt -rsigner ocsp.crt -rkey ocsp.key \
    -reqin req_$n.der -respout ocsp_${n}_delegated.der -ndays 7
done
# The must-staple leaf's own response (for the stapled must-staple case)
q openssl ocsp -issuer ca.crt -cert staple.crt -no_nonce -reqout req_staple.der
q openssl ocsp -index ca/index.txt -CA ca.crt -rsigner ca.crt -rkey ca.key \
  -reqin req_staple.der -respout ocsp_staple_ca.der -ndays 7
# byKey responder ID variant (RFC 6960 4.2.2.1 KeyHash = SHA-1 of the SPKI bits)
q openssl ocsp -index ca/index.txt -CA ca.crt -rsigner ca.crt -rkey ca.key -resp_key_id \
  -reqin req_good.der -respout ocsp_good_ca_keyid.der -ndays 7
# SHA-256 CertID + nonce variant
q openssl ocsp -sha256 -issuer ca.crt -cert good.crt -reqout req_good_sha256.der
q openssl ocsp -index ca/index.txt -CA ca.crt -rsigner ca.crt -rkey ca.key \
  -reqin req_good_sha256.der -respout ocsp_good_sha256_nonce.der -ndays 7
# A non-successful response (unauthorized = 6) for an unknown issuer
q openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -keyout other.key -out other.crt \
  -config ca.cnf -subj "/CN=Other CA" -extensions ext_ca
q openssl ocsp -issuer other.crt -cert other.crt -no_nonce -reqout req_other.der
q openssl ocsp -index ca/index.txt -CA ca.crt -rsigner ca.crt -rkey ca.key \
  -reqin req_other.der -respout ocsp_unauthorized.der -ndays 7 || true
# Intermediate CA "sub" under the root, a leaf under it, an (empty) CRL
# signed by sub that covers that leaf, and a root CRL that lists sub as
# revoked. Consumers use these to check that revocation is evaluated
# for every certificate below the trust anchor, not the leaf alone.
# Done last so the root's earlier CRL (crl.der) and OCSP responses are
# unaffected by sub's revocation.
q openssl req -newkey rsa:2048 -nodes -keyout sub.key -out sub.csr -config ca.cnf -subj "/CN=SPARKx509 Sub CA"
q openssl ca -batch -config ca.cnf -extensions ext_ca -in sub.csr -out sub.crt -notext
mkdir -p subca; touch subca/index.txt; echo 2000 > subca/serial; echo 01 > subca/crlnumber
sed 's#dir = ./ca$#dir = ./subca#; s#^certificate = ca.crt$#certificate = sub.crt#; s#^private_key = ca.key$#private_key = sub.key#' ca.cnf > subca.cnf
q openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout sub_leaf.key -out sub_leaf.csr \
  -config ca.cnf -subj "/CN=subleaf.test"
q openssl ca -batch -config subca.cnf -extensions ext_leaf -in sub_leaf.csr -out sub_leaf.crt -notext
q openssl ca -batch -config subca.cnf -gencrl -out crl_sub_empty.pem
openssl crl -in crl_sub_empty.pem -outform DER -out crl_sub_empty.der
q openssl ca -batch -config ca.cnf -revoke sub.crt -crl_reason cACompromise
q openssl ca -batch -config ca.cnf -gencrl -out crl_root_sub_revoked.pem
openssl crl -in crl_root_sub_revoked.pem -outform DER -out crl_root_sub_revoked.der
for f in ca good revoked staple ocsp shard1 shard2 sub sub_leaf; do openssl x509 -in $f.crt -outform DER -out $f.der; done
# Fixture clock for consumers (sparktls test_revocation): line 1 = generation
# time + 1 h (safely after every thisUpdate, inside the 7-day nextUpdate),
# line 2 = generation time + 30 d (past nextUpdate, for the "expired" cases).
# Format per line: "YYYY MM DD HH MM SS" in UTC.
{
  date -u -d @$((GEN_EPOCH + 3600))      "+%Y %m %d %H %M %S"
  date -u -d @$((GEN_EPOCH + 30*86400))  "+%Y %m %d %H %M %S"
} > now.txt
echo "fixtures in $OUT"; ls *.der
