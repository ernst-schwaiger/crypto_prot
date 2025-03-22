#!/bin/bash

SCRIPT_DIR="$(dirname "$0")"

if [ ! -d "${SCRIPT_DIR}/generated" ]; then
    echo "${SCRIPT_DIR}/generated does not exist, generating keys and certs..."
    
    mkdir -p "${SCRIPT_DIR}/generated"

    # Private key for the self-signed/root certificate
    openssl genrsa -out ${SCRIPT_DIR}/generated/rootCA.key 2048
    # Generate the self-signed/root certificate
    openssl req -x509 -new -nodes -key ${SCRIPT_DIR}/generated/rootCA.key -sha256 -days 365 -out ${SCRIPT_DIR}/generated/rootCA.crt < ${SCRIPT_DIR}/rootCertProps.txt

    # Generate a private key for the server certificate
    openssl genrsa -out ${SCRIPT_DIR}/generated/serverCert.key 2048
    # Certificate signing request
    openssl req -new -key ${SCRIPT_DIR}/generated/serverCert.key -out ${SCRIPT_DIR}/generated/serverCert.csr < ${SCRIPT_DIR}/serverCertProps.txt
    # Sign the server certificate
    openssl x509 -req -in ${SCRIPT_DIR}/generated/serverCert.csr -CA ${SCRIPT_DIR}/generated/rootCA.crt -CAkey ${SCRIPT_DIR}/generated/rootCA.key -CAcreateserial \
        -out ${SCRIPT_DIR}/generated/serverCert.crt -days 365 -sha256

    # Generate a private key for the client certificate
    openssl genrsa -out ${SCRIPT_DIR}/generated/clientCert.key 2048
    # Certificate signing request
    openssl req -new -key ${SCRIPT_DIR}/generated/clientCert.key -out ${SCRIPT_DIR}/generated/clientCert.csr < ${SCRIPT_DIR}/clientCertProps.txt
    # Sign the server certificate
    openssl x509 -req -in ${SCRIPT_DIR}/generated/clientCert.csr -CA ${SCRIPT_DIR}/generated/rootCA.crt -CAkey ${SCRIPT_DIR}/generated/rootCA.key -CAcreateserial \
        -out ${SCRIPT_DIR}/generated/clientCert.crt -days 365 -sha256
fi
