#!/bin/bash
# Generate self-signed SSL certificates for development

mkdir -p docker/ssl

# Generate private key
openssl genrsa -out docker/ssl/key.pem 2048

# Generate certificate
openssl req -new -x509 -key docker/ssl/key.pem -out docker/ssl/cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

echo "SSL certificates generated in docker/ssl/"