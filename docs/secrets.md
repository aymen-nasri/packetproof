# Secrets: what is secret, where it lives, how it changes

**Status, 2026-11-10:** the age key exists (recipient
`age1f804f0j6hh9kmgmxtsydfn025j7drsuy2s2ncvesuyh6ad834gxs6kqt5z`), and
[secrets-bootstrap run 42876173273](https://github.com/aymen-nasri/packetproof/actions/runs/42876173273)
created the identities now committed in `secrets/`. Prod run
[42883900778](https://github.com/aymen-nasri/packetproof/actions/runs/42883900778) checked that prod runs them: both routers' own and peer WireGuard
keys, the CA root's fingerprint, and the served certificate against the committed root all match
([prod.md](prod.md#prod-with-long-lived-identities-from-sops)).

PacketProof has two kinds of lab, and they treat secrets differently on purpose.

| | Pull-request lab (Gate 2, Gate 3) | Prod (prod.yml) |
|---|---|---|
| WireGuard private keys | generated inside each router at start-up; never leave it | long-lived, from `secrets/prod.sops.yaml`, piped into each router |
| CA root | fresh each run, created by `step ca init` inside the CA container | long-lived, from `secrets/prod.sops.yaml`, mounted read-only into the CA container for its start-up |
| Who can read the plaintext | nobody: it never leaves the container | the prod job, for the seconds it takes to start the lab |

Throwaway identities are right for a pull request: nothing about them needs to survive the run, and
nothing can leak from a run that never had them. Prod is different. A real network keeps its tunnel
keys and its trust anchor across changes, so prod does too, and the pipeline has to handle real
secrets the way an operator would.

## The pieces

- **age key pair.** The private key is the `SOPS_AGE_KEY` secret of the repository's `prod`
  environment; only jobs that run from `main` can read it. The public key is the repository
  variable `SOPS_AGE_RECIPIENT`. Both are set by `scripts/bootstrap-sops-key.ps1`, which the
  repository owner runs on their own machine. It pipes the key into `gh secret set` and deletes it,
  so the key is never printed, pasted, or seen by anyone else, including the assistant that wrote
  the script.
- **`secrets/prod.sops.yaml`.** Committed, but encrypted with SOPS to that age recipient: both site
  routers' WireGuard private keys and the CA root's certificate and key. Every value is AES-256-GCM
  ciphertext; the keys stay readable, so a diff shows *which* secret changed without showing it.
- **`secrets/prod-public.yaml`.** Committed in clear: the matching WireGuard public keys, the CA
  root certificate, and its SHA-256 fingerprint. This is what prod is checked against.
- **`secrets-bootstrap.yml`.** A manual workflow that creates new identities. Keys are generated
  with the lab's own images (`wg genkey`, `step certificate create`) on a GitHub runner, encrypted
  there, and handed out as an artifact that holds only the ciphertext and the public half. Before
  the upload, the workflow checks that the ciphertext contains none of the plaintext keys.

## How prod uses them

1. A step that is the only one with `SOPS_AGE_KEY` in its environment decrypts
   `secrets/prod.sops.yaml` to a file under the runner's temp directory (mode 0600).
2. `make deploy SECRETS=...` starts the lab. Each router first generates a throwaway key at boot, as
   in a pull-request lab. `lab.exchange_keys` then pipes the managed key into the router with
   `docker exec -i` and `wg set wg0 private-key`, so the key goes from memory into the router and is
   never written to the runner's disk. The CA root is written to the render directory for the CA
   container's start-up, and `step ca init --root --key` signs a fresh intermediate with it.
3. Once the lab is ready, the root key file is deleted, and the workflow deletes the decrypted file.
4. Step 5c (`scripts/prod.py identities`) checks prod against `secrets/prod-public.yaml`:
   - each router's own WireGuard public key is the managed one, and its peer is the other managed
     key;
   - the CA root that the lab publishes has the committed fingerprint;
   - the certificate HAProxy serves verifies against the committed root itself, not only against
     the lab's own copy.

If the secret or the encrypted file is missing, prod says so in its summary ("No SOPS-managed
identities configured") and runs with throwaway identities, as a pull-request lab does. It does not
claim the check passed.

## Rotation

| What | How | Proof |
|---|---|---|
| The age key (who can decrypt) | `sops updatekeys` or re-encrypt to a new recipient, then delete the old key | `secrets.yml`: a rotation test with throwaway keys shows the new key decrypts, the old key no longer does, and the values did not change |
| The identities themselves | run `secrets-bootstrap.yml`, commit its ciphertext and public file in a pull request | the next prod run's step 5c checks the new keys and root |
| A leaked age key | run `bootstrap-sops-key.ps1` again, then `secrets-bootstrap.yml`: new key **and** new identities, because whoever held the old key could decrypt the old ciphertext from git history | as above |

Rotating only the age key does not protect secrets that were already readable with the old one:
git history keeps the old ciphertext. That is why a leaked key means new identities too.

## What went wrong the first time

The first prod run with the managed identities
([42878657349](https://github.com/aymen-nasri/packetproof/actions/runs/42878657349)) stopped at the
decrypt step, before any lab was built: SOPS could not parse the age key ("unknown identity type").
The bootstrap script had piped the key into `gh secret set`, and Windows PowerShell 5.1 sends piped
text to a native program with a UTF-8 byte-order mark in front and a CRLF behind
(`\xef\xbb\xbfAGE-SECRET-KEY-1...\r\n`). The key itself was intact. The script now hands the key to
`gh` in a file written as plain ASCII, and prod strips a byte-order mark and CRs from the key before
using it, so the stored secret did not have to be replaced. The next run then showed a second bug,
in the check rather than in prod: it read the CA root from the runner's disk, where the CA writes it
with mode 0600. It now reads it inside the lab.

## Limits

- The plaintext exists for a few seconds on a GitHub-hosted runner. Anyone who controls that
  runner or the `main` branch can read it. The defences are the same as for the rest of the
  pipeline: the ruleset on `main`, SHA-pinned actions, a read-only default token, and an
  environment that only `main` can use.
- The CA root key is on the runner's disk, in a directory bind-mounted read-only into one
  container, from deploy until the lab is ready. A pull-request lab never has it.
- There is no HSM and no online revocation. This is a lab's trust anchor, not a production PKI.
