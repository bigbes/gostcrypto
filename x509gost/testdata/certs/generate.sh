#!/bin/sh
# generate.sh — regenerate the externally-signed GOST certificate fixtures used
# by TestVerify_GOST_ExternalFixture and TestVerify_GOST_ExternalChain.
#
# This script is DOCUMENTATION, not part of the test run: the tests load the
# committed *.crt PEMs and never invoke openssl. It records exactly how the
# fixtures were produced so they can be regenerated against an independent
# implementation (OpenSSL 3 + gost-engine 3.0.3), pinning the GOST certificate
# wire format (BIT STRING signature ordering, LE(X)||LE(Y) public key encoding,
# the signwithdigest-vs-pubkey OID distinction) against this module's parser.
#
# Requirements (macOS / Homebrew layout shown; adjust for your platform):
#   - OpenSSL 3 with the GOST engine available.
#   - OPENSSL_CONF pointing at the gost-engine config that loads the engine.
#
# Generated 2026-06-10 with OpenSSL 3.6.2 + gost-engine 3.0.3.
set -eu

OSSL="${OSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}"
export OPENSSL_CONF="${OPENSSL_CONF:-/opt/homebrew/etc/gost/gost-engine.cnf}"

# 1. GOST R 34.10-2012 256-bit self-signed (curve CryptoPro-A, signwithdigest-256).
"$OSSL" req -x509 -newkey gost2012_256 -pkeyopt paramset:A \
  -keyout /tmp/key_256a.pem -out gost256_selfsigned.crt \
  -nodes -days 3650 -subj "/CN=gost256-selfsigned"

# 2. GOST R 34.10-2012 512-bit self-signed (curve TC26-512-A, signwithdigest-512).
"$OSSL" req -x509 -newkey gost2012_512 -pkeyopt paramset:A \
  -keyout /tmp/key_512a.pem -out gost512_selfsigned.crt \
  -nodes -days 3650 -subj "/CN=gost512-selfsigned"

# 3. Mixed-strength chain: a 512-bit CA signing a cert that carries a 256-bit
#    subject key. The leaf's signature OID is signwithdigest-512 (from the CA
#    key) while its SubjectPublicKeyInfo OID is the 256-bit key OID — this is the
#    exact scenario X509-65 regressed on (digest must come from the signature
#    OID, not the subject key OID).
cat > /tmp/ca_ext.cnf <<'EOF'
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
EOF
"$OSSL" req -x509 -newkey gost2012_512 -pkeyopt paramset:A \
  -keyout /tmp/ca512_key.pem -out ca512.crt \
  -nodes -days 3650 -subj "/CN=gost512-ca" \
  -extensions v3_ca -config /tmp/ca_ext.cnf

"$OSSL" req -newkey gost2012_256 -pkeyopt paramset:A \
  -keyout /tmp/leaf256_key.pem -out /tmp/leaf256.csr \
  -nodes -subj "/CN=gost256-leaf"

cat > /tmp/leaf_ext.cnf <<'EOF'
[ v3_leaf ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
"$OSSL" x509 -req -in /tmp/leaf256.csr -CA ca512.crt -CAkey /tmp/ca512_key.pem \
  -CAcreateserial -days 3650 -out leaf256_signedby512.crt \
  -extfile /tmp/leaf_ext.cnf -extensions v3_leaf
