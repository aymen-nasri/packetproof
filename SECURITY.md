# Security policy

## Scope

PacketProof is a lab. Every router, host and service runs in throwaway containers on lab bridges.
WireGuard keys for pull-request labs are generated inside each router at run time and never leave
it. The lab's prod has long-lived identities (two WireGuard keys and a CA root): they are in Git
only as SOPS ciphertext, and the age key that decrypts them is a secret of the `prod` environment,
readable only by workflows running from `main` ([docs/secrets.md](docs/secrets.md)). They protect
nothing outside the lab. Key rotation is proved by a test with throwaway keys.

In scope: the workflows and their permissions, the release and verification chain (signed images,
attested and signed config bundles, signed releases), the handling of prod's SOPS-encrypted
identities, the generator, and anything that could make a gate report a pass it did not earn.

## Reporting a vulnerability

Please report privately, not in a public issue, through GitHub's private vulnerability reporting:
https://github.com/aymen-nasri/packetproof/security/advisories/new

What to expect:

- an acknowledgement within 7 days;
- a fix, or an explanation of why no fix is needed, within 30 days of the acknowledgement;
- credit in the advisory and the fix commit, unless you prefer otherwise;
- coordinated disclosure: the advisory is published once a fix is released, or after 90 days.

## Supported versions

Only the latest release and `main` receive fixes.
