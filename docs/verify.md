# Verify a release yourself

Every file in a PacketProof release can be checked without trusting this repository's word for
it. You need the GitHub CLI (`gh`) and cosign 2.4 or newer. Replace `v1.0.0` with the release you
are checking.

```bash
TAG=v1.0.0
REPO=aymen-nasri/packetproof
OIDC=https://token.actions.githubusercontent.com
gh release download "$TAG" -R "$REPO" -D "packetproof-$TAG" && cd "packetproof-$TAG"
```

## 1. The checksums were signed by the release workflow, for this tag

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "$OIDC"
sha256sum -c SHA256SUMS
```

The signature is keyless: the certificate names the workflow file and the tag that ran it, and the
signing event is in the public Rekor transparency log. A file changed after signing fails
`sha256sum -c`.

## 2. The config bundle has build provenance and its own signature

```bash
gh attestation verify "packetproof-config-$TAG.tgz" -R "$REPO" \
  --signer-workflow "$REPO/.github/workflows/release.yml"
cosign verify-blob "packetproof-config-$TAG.tgz" --bundle "packetproof-config-$TAG.sigstore.json" \
  --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "$OIDC"
```

The attestation records the commit, the workflow, and the runner that built the file (SLSA build
level 2).

## 3. The bundle is the one main built, and you can rebuild it

`bundle-source.txt` holds three values: the commit, the `bundle.yml` run that built that commit's
bundle when it landed on `main`, and the SHA-256 they share. The release workflow rebuilt the
bundle with `make bundle` and refused to publish unless the bytes matched. To rebuild it yourself
on Linux with Python 3.14:

```bash
git clone "https://github.com/$REPO" src && cd src && git checkout "$TAG"
make venv && make bundle BUNDLE=mine.tgz
sha256sum mine.tgz   # compare with packetproof-config-$TAG.tgz
```

A different Python or tar version can change the bytes. The workflow's comparison on two GitHub
runners is the claim this repository makes.

## 4. The lab images are signed, and their SBOMs came from signed attestations

`images.txt` lists both images by digest. For each:

```bash
cosign verify ghcr.io/aymen-nasri/packetproof-router@sha256:... \
  --certificate-identity "https://github.com/$REPO/.github/workflows/images.yml@refs/heads/main" \
  --certificate-oidc-issuer "$OIDC"
cosign verify-attestation --type cyclonedx ghcr.io/aymen-nasri/packetproof-router@sha256:... \
  --certificate-identity "https://github.com/$REPO/.github/workflows/images.yml@refs/heads/main" \
  --certificate-oidc-issuer "$OIDC" > /dev/null
```

`packetproof-router-sbom.cdx.json` and `packetproof-node-sbom.cdx.json` are the predicates of
those attestations, copied out as they were signed. They were not regenerated at release time.

## What this does not prove

- That the network works. The gates, the scorecard and the prod run do that, each with its own
  limits ([limits.md](limits.md)).
- That the build platform is honest. Signatures and provenance tie each file to a GitHub Actions
  run of this repository; they cannot detect a compromised runner or a compromised `main`.
