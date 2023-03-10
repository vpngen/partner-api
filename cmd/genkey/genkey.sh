#!/bin/sh

KEYDIR=${KEYDIR:-$(pwd)}
KEYTYPE=${KEYTYPE:-"ed25519"}

if [ ! -d "${KEYDIR}" ]; then 
        echo "Key dir ${KEYDIR} does not exist"
        exit 1
fi

NAME="${1}"
if [ "x" = "x${NAME}" ]; then 
        echo "Name can't be empty"
        exit 1
fi

newkey="${KEYDIR}/id_${KEYTYPE}.${NAME}"
if [ -e "${newkey}" ]; then
        echo "Key ${newkey} already exists"
        exit 1
fi

ALLOWED=${2:-"0.0.0.0/0"}

TOKEN=$(dd if=/dev/urandom bs=32 count=1 status=none | basenc --base64url)

dgst=$(echo "${TOKEN}" | openssl dgst -binary -sha256 | basenc --base64)

comment=";${dgst};${ALLOWED}"

if ! ssh-keygen -q -t "${KEYTYPE}" -P "" -C "${comment}" -f "${newkey}"; then 
        echo "Can't create key!"
        exit 1
fi

if [ ! -s "${newkey}.pub" ]; then
        echo "Can't find pubkey: ${newkey}.pub"
        exit 1
fi

keyfp=$(ssh-keygen -l -f "${newkey}.pub" | grep -o "SHA256\:[^_[:space:]]*")

echo "NAME: ${NAME}"
echo "COMMENT: ${comment}"
echo "KEY FILE: ${newkey}"
echo "TOKEN: ${TOKEN}"
echo "SSH PUBKEY FP: ${keyfp}"
echo "SSH PUBKEY:"
cut -f 1,2 -d ' ' < "${newkey}.pub" | xargs -I %R echo "%R ${NAME}"

