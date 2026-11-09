# PacketProof

Prove every network change before it merges.

PacketProof will be a small two-site company network written as code. FRRouting routers exchange
BGP over a WireGuard tunnel, nftables firewalls split the network into zones and do NAT, and the
network has split-horizon DNS, a step-ca certificate authority and an HAProxy reverse proxy. Every
pull request is meant to be rebuilt as a disposable containerlab copy on a free GitHub Actions
runner and must prove its routing, segmentation, DNS and TLS before it merges. The gates themselves
will be graded against deliberately broken changes and attack paths.

## Status

**Week 1: go/no-go checks. None of the network described above is built yet.** This week tests
whether the tools the design depends on (containerlab on a free runner, Batfish reading FRR
configs, WireGuard inside containers, the CI time budget, and local development on Windows 10)
actually hold. Each result will be recorded with a link to its CI run.

The rules that judge every result are in [docs/method.md](docs/method.md): the week-1 pass rules,
the hand-written invariants, 30 planted faults and 12 attack paths. That file was committed before
any test code existed, so results cannot shape the rules that judge them.

## Security

Every action is pinned to a full commit SHA, the default workflow token is read-only, and every
push and pull request is checked by Gitleaks (secrets in the whole history) and zizmor (unsafe
workflow patterns). See [SECURITY.md](SECURITY.md) to report a problem.

## License

[Apache-2.0](LICENSE)
