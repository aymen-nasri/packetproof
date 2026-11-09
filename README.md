# PacketProof

Prove every network change before it merges.

PacketProof will be a small two-site company network written as code. FRRouting routers exchange
BGP over a WireGuard tunnel, nftables firewalls split the network into zones and do NAT, and the
network has split-horizon DNS, a step-ca certificate authority and an HAProxy reverse proxy. Every
pull request is meant to be rebuilt as a disposable containerlab copy on a free GitHub Actions
runner and must prove its routing, segmentation, DNS and TLS before it merges. The gates themselves
will be graded against deliberately broken changes and attack paths.

## Status

**Week 1 is done: the go/no-go checks. The network described above is not built yet.** Week 1
tested whether the tools the design depends on actually hold. Results, each linked to its CI run,
are in [docs/go-no-go.md](docs/go-no-go.md):

| Assumption | Verdict |
|---|---|
| containerlab runs on a free runner | GO: 5 of 5 runs, about 22 s to deploy and check |
| Batfish reads the generated FRR configs | GO, and it caught a planted prefix-list leak; it cannot see whether the WireGuard tunnel is up |
| WireGuard works inside containers | GO: 5 of 5 runs, BGP over the tunnel, capture shows no clear traffic |
| The CI time budget holds | GO: one full run 87 s, one planted fault 23 s (single measurements) |
| The Windows 10 laptop can run the lab | NO-GO (not attempted): development happens in CI |

The rules that judge every result are in [docs/method.md](docs/method.md): the week-1 pass rules,
the hand-written invariants, 30 planted faults and 12 attack paths. That file was committed before
any test code existed, so results cannot shape the rules that judge them.

## Security

Every action is pinned to a full commit SHA, the default workflow token is read-only, and every
push and pull request is checked by Gitleaks (secrets in the whole history) and zizmor (unsafe
workflow patterns). See [SECURITY.md](SECURITY.md) to report a problem.

## License

[Apache-2.0](LICENSE)
