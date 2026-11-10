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
rm lab.yaml

WG='["wireguard"]["rtr-a_private_key"]'
CA='["ca"]["intermediate_password"]'
value() { SOPS_AGE_KEY_FILE="$1" sops decrypt --extract "$2" lab.sops.yaml 2>/dev/null || true; }
# From here on every check reports instead of aborting the script.
set +e
fail=0
result() { if [ "$1" = 0 ]; then echo "- PASS: $2"; else echo "- FAIL: $2"; fail=1; fi; }

echo "### SOPS + age rotation test"
grep -qF -- "$wg_key" lab.sops.yaml || grep -qF -- "$ca_pw" lab.sops.yaml; leaked=$?
[ "$leaked" = 1 ]; result $? "the encrypted file contains neither secret value"
[ "$(value old.key "$WG")" = "$wg_key" ] && [ "$(value old.key "$CA")" = "$ca_pw" ]; result $? "the old key decrypts both values before rotation"
[ -z "$(value new.key "$WG")" ]; result $? "the new key cannot decrypt before it is added"
cipher_before=$(grep -o 'ENC\[AES256_GCM,data:[^,]*' lab.sops.yaml | sort | sha256sum)
n_values=$(grep -c 'ENC\[AES256_GCM' lab.sops.yaml)

# Rotate: a new data key, the new recipient added, the old recipient removed.
cp lab.sops.yaml lab.sops.yaml.before
if ! SOPS_AGE_KEY_FILE=old.key sops rotate --in-place --add-age "$new_pub" --rm-age "$old_pub" lab.sops.yaml; then
  echo "- FAIL: the rotation command itself failed"
  exit 1
fi
cipher_after=$(grep -o 'ENC\[AES256_GCM,data:[^,]*' lab.sops.yaml | sort | sha256sum)
changed=$(comm -12 <(grep -o 'ENC\[AES256_GCM,data:[^,]*' lab.sops.yaml.before | sort) \
                   <(grep -o 'ENC\[AES256_GCM,data:[^,]*' lab.sops.yaml | sort) | wc -l)

[ "$(value new.key "$WG")" = "$wg_key" ] && [ "$(value new.key "$CA")" = "$ca_pw" ]; result $? "the new key decrypts both values, unchanged, after rotation"
[ -z "$(value old.key "$WG")" ]; result $? "the old key no longer decrypts"
[ "$cipher_before" != "$cipher_after" ] && [ "$changed" = 0 ] && [ "$n_values" -ge 2 ]
result $? "all $n_values encrypted values (the MAC included) were re-encrypted; sops rotate also replaces the data key, which this test cannot see"
! grep -qF -- "$old_pub" lab.sops.yaml; result $? "the old recipient is gone from the file"
exit "$fail"
