# 2. "The frontend cannot reach the API"

Planted fault **F30**: the `proxy-to-app` flow removed from `network.yaml`. Evidence: Gate 3 run
[42717245768](https://github.com/aymen-nasri/packetproof/actions/runs/42717245768), artifact
`gate3-F30`.

**Symptom.** Every HTTPS request, from inside and from the internet, returns:

```
<html><body><h1>503 Service Unavailable</h1>
No server is available to handle this request.
</body></html>
```

The TLS handshake succeeds and the certificate is valid. A 1 MiB download returns 107 bytes: the
error page.

**First guesses.** The apps crashed; HAProxy is misconfigured; DNS points at the wrong backend.

**Commands, in the order DNS, route, port, firewall.**

1. *DNS:* the inside view still answers `www -> 172.16.20.10` (all DNS tests passed).
2. *Route:* haproxy and the apps share rtr-a; no routing involved beyond the gateway.
3. *Port:* the app servers started normally (their readiness checks passed).
4. *Firewall:* from haproxy, `pp-probe.py tcp 172.16.30.11 8080` returns `filtered`, and the same
   for app2. No answer at all: the packets are dropped, not refused.

"No server is available to handle this request" is HAProxy saying every server in the backend is
marked down: its health checks cannot reach either app, so it has nowhere to send the request.

**Root cause.** The intent no longer allows DMZ to APP on 8080, so rtr-a's forward chain falls
through to its default drop.

**Fix.** Restore the flow `haproxy -> app1, app2 tcp/8080`.

**Prevention, and which gate caught it.** Gate 1 caught it first: the Conftest invariant INV-12
lists the exact allowed flows and reported `expected flow "proxy-to-app" is missing`. Gate 2 caught
it as well: the allow matrix, the proxy tests, the TLS test and the HTTPS probe in monitoring.
