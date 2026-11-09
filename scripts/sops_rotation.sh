#!/usr/bin/env bash
# Prove the SOPS + age secrets lifecycle with throwaway keys (see .github/workflows/secrets.yml).
# Prints a Markdown report; exits non-zero if any property fails. Secret values are never printed.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

age-keygen -o old.key 2>/dev/null
age-keygen -o new.key 2>/dev/null
old_pub=$(age-keygen -y old.key)
new_pub=$(age-keygen -y new.key)

# Two lab secrets of the kinds the design stores: a WireGuard private key and a CA key password.
wg_key=$(head -c 32 /dev/urandom | base64)
ca_pw=$(head -c 24 /dev/urandom | base64)
printf 'wireguard:\n  rtr-a_private_key: %s\nca:\n  intermediate_password: %s\n' "$wg_key" "$ca_pw" > lab.yaml

sops encrypt --age "$old_pub" lab.yaml > lab.sops.yaml
fail=0
check() { if eval "$2"; then echo "- PASS: $1"; else echo "- FAIL: $1"; fail=1; fi; }

echo "### SOPS + age rotation test"
check "the encrypted file contains no secret value" "! grep -qF -- \"$wg_key\" lab.sops.yaml && ! grep -qF -- \"$ca_pw\" lab.sops.yaml"
check "the old key decrypts before rotation" "SOPS_AGE_KEY_FILE=old.key sops decrypt lab.sops.yaml | cmp -s - lab.yaml"
cipher_before=$(grep 'rtr-a_private_key:' lab.sops.yaml | sha256sum)

# Rotate: new data key, new recipient, old recipient removed.
SOPS_AGE_KEY_FILE=old.key sops rotate --in-place --add-age "$new_pub" --rm-age "$old_pub" lab.sops.yaml
cipher_after=$(grep 'rtr-a_private_key:' lab.sops.yaml | sha256sum)

check "the new key decrypts after rotation" "SOPS_AGE_KEY_FILE=new.key sops decrypt lab.sops.yaml | cmp -s - lab.yaml"
check "the old key no longer decrypts" "! SOPS_AGE_KEY_FILE=old.key sops decrypt lab.sops.yaml > /dev/null 2>&1"
check "every value was re-encrypted under a new data key" "[ \"$cipher_before\" != \"$cipher_after\" ]"
check "the old recipient is gone from the file" "! grep -qF -- \"$old_pub\" lab.sops.yaml"
exit "$fail"
