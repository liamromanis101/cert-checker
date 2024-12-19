#!/bin/bash

CERT_DIR=${1:-$(pwd)}
OUTPUT_FILE="cert_security_report.csv"
echo "Filename,Issuer,Subject,Valid From,Valid To,Key Usage,Extended Key Usage,Signature Algorithm,Signature Secure?,Key Strength,SHA-256 Fingerprint,SHA-1 Fingerprint,SANs,Revocation Info,CRL Present,OCSP URL,Certificate Policies,Basic  Constraints,Is CA?,SCTs Present,Key Pair Match" > "$OUTPUT_FILE"


process_certificate() {
    CERT_FILE=$1
    ISSUER=$(openssl x509 -in "$CERT_FILE" -noout -issuer | sed 's/issuer= //')
    SUBJECT=$(openssl x509 -in "$CERT_FILE" -noout -subject | sed 's/subject= //')
    VALID_FROM=$(openssl x509 -in "$CERT_FILE" -noout -startdate | sed 's/notBefore=//')
    VALID_TO=$(openssl x509 -in "$CERT_FILE" -noout -enddate | sed 's/notAfter=//')
    KEY_USAGE=$(openssl x509 -in "$CERT_FILE" -text -noout | grep -A1 "Key Usage" | tail -1 | tr -d '\n')
    EXTENDED_KEY_USAGE=$(openssl x509 -in "$CERT_FILE" -text -noout | grep -A1 "Extended Key Usage" | tail -1 | tr -d '\n')
    SIG_ALGO=$(openssl x509 -in "$CERT_FILE" -text -noout | grep "Signature Algorithm" | head -n 1 | awk '{print $3}')
    KEY_STRENGTH=$(openssl x509 -in "$CERT_FILE" -text -noout | grep "Public-Key" | awk '{print $2}' | tr -d "()")


    if echo "$SIG_ALGO" | grep -Eq "sha256|sha384|sha512"; then
        SIGNATURE_SECURE="Yes"
    else
        SIGNATURE_SECURE="No (Weak algorithm)"
    fi

    SHA256_FINGERPRINT=$(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 | cut -d= -f2)
    SHA1_FINGERPRINT=$(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha1 | cut -d= -f2)
    SAN=$(openssl x509 -in "$CERT_FILE" -text -noout | grep -A1 "Subject Alternative Name" | tail -1 | tr -d '\n')
    CRL_INFO=$(openssl x509 -in "$CERT_FILE" -text -noout | grep -A2 "CRL Distribution Points" | tail -1 | tr -d '\n')
    OCSP_URL=$(openssl x509 -in "$CERT_FILE" -text -noout | grep -A1 "Authority Information Access" | grep "OCSP" | awk -F':' '{print $2 ":" $3}' | tr -d ' ')
    CERT_POLICIES=$(openssl x509 -in "$CERT_FILE" -text -noout | grep -A1 "Certificate Policies" | tail -1 | tr -d '\n')
    BASIC_CONSTRAINTS=$(openssl x509 -in "$CERT_FILE" -text -noout | grep -A1 "Basic Constraints" | tail -1 | tr -d '\n')
    IS_CA=$(echo "$BASIC_CONSTRAINTS" | grep -q "CA:TRUE" && echo "Yes" || echo "No")
    SCTS_PRESENT=$(openssl x509 -in "$CERT_FILE" -text -noout | grep -q "Signed Certificate Timestamp" && echo "Yes" || echo "No")
    CERT_MODULUS=$(openssl x509 -noout -modulus -in "$CERT_FILE" | openssl md5)
    PRIVATE_KEY_FILE="${CERT_FILE%.*}.key"
 

    if [[ -f "$PRIVATE_KEY_FILE" ]]; then
        KEY_MODULUS=$(openssl rsa -noout -modulus -in "$PRIVATE_KEY_FILE" | openssl md5)
        if [[ "$CERT_MODULUS" == "$KEY_MODULUS" ]]; then
            KEY_PAIR_MATCH="Yes"
        else
            KEY_PAIR_MATCH="No"
        fi
    else
        KEY_PAIR_MATCH="Private key not found"
    fi
 
    echo "\"$CERT_FILE\",\"$ISSUER\",\"$SUBJECT\",\"$VALID_FROM\",\"$VALID_TO\",\"$KEY_USAGE\",\"$EXTENDED_KEY_USAGE\",\"$SIG_ALGO\",\"$SIGNATURE_SECURE\",\"$KEY_STRENGTH\",\"$SHA256_FINGERPRINT\",\"$SHA1_FINGERPRINT\",\"$SAN\",\"$CRL_INFO\",\"$CRL_INFO\",\"$OCSP_URL\",\"$CERT_POLICIES\",\"$BASIC_CONSTRAINTS\",\"$IS_CA\",\"$SCTS_PRESENT\",\"$KEY_PAIR_MATCH\""  >> "$OUTPUT_FILE"
}

 

for CERT_FILE in "$CERT_DIR"/*.{cer,pem,crt}; do
    if [[ -f "$CERT_FILE" ]]; then
        process_certificate "$CERT_FILE"
    fi
done
 
echo "Security report generated: $OUTPUT_FILE"
