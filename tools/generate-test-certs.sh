#!/usr/bin/env bash
set -ex
rm -rf *.pem *.csr certindex* crlnumber
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";

CERT_CNFS_DIR=${SCRIPT_DIR}/certs-cnfs

# # generate root ca

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ./root-key.pem

openssl req -new -x509 -config ${CERT_CNFS_DIR}/root-ca.cnf -key ./root-key.pem  -days 36500 -out ./root-cert.pem

touch ./certindex && echo 1000 > ./certserial && echo 1000 > ./crlnumber

# generate middle ca

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ./ca-key.pem

openssl req -new -config ${CERT_CNFS_DIR}/ca.cnf -key ./ca-key.pem -days 36500 -out ./ca-cert.csr

openssl ca -batch -config  ${CERT_CNFS_DIR}/sign.cnf -in ./ca-cert.csr -out ./ca-cert.pem


cat ca-cert.pem root-cert.pem > cert-chain.pem 
