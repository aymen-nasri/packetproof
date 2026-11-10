# 4. "Which certificate error is this, and why?"

Planted fault **F29**: HAProxy's certificate requested for `haproxy.packetproof.example` instead of
`www`. Evidence: Gate 3 run [42717245768](https://github.com/aymen-nasri/packetproof/actions/runs/42717245768),
artifact `gate3-F29`. The baseline's own TLS tests show the other two errors on purpose.

**Symptom.**

```
curl: (60) SSL: no alternative certificate subject name matches target hostname 'www.packetproof.example'
```

**Reading the certificate.**

```
client-a$ openssl s_client -connect 172.16.20.10:443 -servername www.packetproof.example \
            | openssl x509 -noout -issuer -ext subjectAltName -dates
issuer=O=PacketProof Lab CA, CN=PacketProof Lab CA Intermediate CA
X509v3 Subject Alternative Name: DNS:haproxy.packetproof.example
notBefore=Nov  9 23:10:55 2026 GMT
notAfter=Nov 10 23:11:55 2026 GMT
```

The issuer is right (the lab CA), the dates are right (valid now, 24 hours, as ACME issues), and
the chain verifies. Only the name is wrong.

**The three errors a client can give, and what each means.** Gate 2 triggers all three on purpose:

| Client says | Means | Gate 2 test |
|---|---|---|
| `hostname mismatch` / `no alternative certificate subject name matches` | the certificate is fine but issued for another name | `test_wrong_name_refused`, and F29 |
| `certificate has expired` | the name and the issuer are fine, the dates are not | `test_expired_certificate_refused` |
| `unable to get local issuer certificate` | the client cannot chain it to a CA it trusts | `test_untrusted_issuer_refused` |

The expired test also taught a lesson about the tests themselves: the first version served the
expired certificate without its intermediate, so the client failed on the issuer before ever
checking the date. Order matters: OpenSSL builds the chain before it checks validity.

**Fix.** Request the certificate for the name clients use: `names: [www.packetproof.example]`.

**Prevention, and which gate caught it.** Gate 1 caught it: INV-10 says the proxy's certificate
must cover the name it serves, and Conftest compared `pki.certificates` with `proxy.certificate`.
Gate 2 caught it too: 11 tests.
