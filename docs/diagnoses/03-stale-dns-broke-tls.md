# 3. "A stale DNS record took TLS down with it"

Planted fault **F24**: the inside view's `www` points at 172.16.20.99, an old address. Evidence:
Gate 3 run [42717245768](https://github.com/aymen-nasri/packetproof/actions/runs/42717245768),
artifact `gate3-F24`.

**Symptom.** Inside users time out on `https://www.packetproof.example/`. Outside users get
"connection refused" on the public address, which is odd, because the public DNS view was not
touched. Monitoring shows HTTPS and TLS probes failing, DNS probe fine.

**First guesses.** Two separate problems, one inside and one outside; or the proxy crashed.

**Commands.**

```
client-a$ dig @172.16.50.53 www.packetproof.example +short
172.16.20.99                     <- expected 172.16.20.10
ca$ dig @172.16.50.53 www.packetproof.example +short
172.16.20.99                     <- the CA gets the same answer
haproxy$ tail /tmp/pp-start.log
Using Standalone Mode HTTP challenge to validate www.packetproof.example . Error!
step-ca log: "type":"urn:ietf:params:acme:error:connection"   (6 times)
outside$ nmap -p 1-1024 198.51.100.65
53/tcp open                      <- 443 is no longer open
```

**Root cause.** One stale record, two failures. Inside users went to an address where nothing
listens. Worse, the CA validates ACME HTTP-01 challenges by resolving the name it is asked to
certify and connecting to it on port 80, through the same resolver. It connected to `.99`, failed,
and refused to issue. HAProxy never got a certificate and never started, so port 443 was closed for
the outside too, even though the outside view of DNS was correct.

**Fix.** Point `www` back at haproxy. The intent should name the host, `www: haproxy`, never a
literal address: the generator then follows the host if it moves.

**Prevention, and which gate caught it.** Gate 1 passed it: no invariant says what `www` must
resolve to. Gate 2 caught it with 19 failing tests, in DNS, TLS, NAT, proxy and monitoring. The
lesson for interviews: when "inside and outside both broke", look for the one dependency they share.
Here that dependency was certificate issuance.
