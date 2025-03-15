#!/bin/bash

# Private key for the self-signed/root certificate
openssl genrsa -out rootCA.key 2048
# Generate the self-signed/root certificate
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 365 -out rootCA.crt < ./rootCertProps.txt

# Generate a private key for the server certificate
openssl genrsa -out serverCert.key 2048
# Certificate signing request
openssl req -new -key serverCert.key -out serverCert.csr < ./serverCertProps.txt
# Sign the server certificate
openssl x509 -req -in serverCert.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
    -out serverCert.crt -days 365 -sha256


