#!/bin/sh

set -x
set -o pipefail

SIGNER_NAME=$1
SIGNER_PASSWD=$2

# set node keys
printf "---------------------------- CALLING set-cryptonote-keys... ----------------------------\n"
until printf "$SIGNER_PASSWD\n" | thornode tx thorchain set-cryptonote-keys $SIGNER_NAME $SIGNER_PASSWD --from $SIGNER_NAME --keyring-backend=file --chain-id thorchain --yes; do
  sleep 5
done
printf "---------------------------- CALLING set-cryptonote-keys ENDS ----------------------------"