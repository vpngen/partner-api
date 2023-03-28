#!/bin/sh

printdef () {
        exit 1
}

# Base64Url encode the header and payload
base64UrlEncode() {
    echo -n "$1" | openssl enc -a -A | tr '+/' '-_' | tr -d '='
}

TOKEN_FILE=${TOKEN_FILE:-$(pwd)/token.lst}
if [ -z "${JWT_SIGN_KEY}" ]; then
        echo "JWT_SIGN_KEY is not set"
        echo "Please set JWT_SIGN_KEY in your environment"
        echo "or pass it as an argument to this script"
        echo "e.g. JWT_SIGN_KEY=your_secret_key $0"
        echo
        printdef
fi

if [ -n "$1" ]; then
        ALLOWED_PREFIXES="$1"
fi

while true; do
        NAME=$(dd if=/dev/urandom bs=1 count=8 2>/dev/null | base32 | tr -d '=' | tr '[:upper:]' '[:lower:]')

        # Define the payload
        payload='{"name":"'"${NAME}"'"}'
        payload_encoded=$(base64UrlEncode "$payload")

        if [ -f "${TOKEN_FILE}" ]; then
                if grep "^${payload_encoded}" "${TOKEN_FILE}" >/dev/null 2>&1; then
                        echo "Token already exists"
                        continue
                fi
        fi

        break
done

echo "Generated token name: ${NAME}"

# Define the header
header='{"alg":"HS256","typ":"JWT"}'
header_encoded=$(base64UrlEncode "$header")

# Create the signature
signature=$(echo -n "${header_encoded}.${payload_encoded}" | openssl dgst -binary -sha256 -hmac "${JWT_SIGN_KEY}" | openssl enc -a -A | tr '+/' '-_' | tr -d '=')

# Concatenate the header, payload, and signature to create the JWT
jwt="${header_encoded}.${payload_encoded}.${signature}"

dgst=$(echo -n "${jwt}" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
echo "JWT digest: ${dgst}"

# Output the JWT token
echo "Generated JWT: $jwt"

if [ -n "${ALLOWED_PREFIXES}" ]; then
        echo "Allowed prefixes: ${ALLOWED_PREFIXES}"
        echo "${jwt},${ALLOWED_PREFIXES}" >> "${TOKEN_FILE}"
else
        echo "${jwt}" >> "${TOKEN_FILE}"
fi