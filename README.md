# DANE / TLSA Inspector

A free, single-page DANE / TLSA record inspector, certificate matcher and TLSA generator (RFC 6698, RFC 7671, RFC 7672). Live at [dane.hbenali.ovh](https://dane.hbenali.ovh).

No backend, no build step, no dependencies: static HTML, CSS and one small script calling a public DNS-over-HTTPS API from the browser.

## Features

- **Mail mode**: looks up a domain's MX records, then the TLSA record at `_25._tcp.<mx-host>` for each host
- **Custom host and port**: TLSA name `_<port>._tcp.<host>` (default port 443)
- **Plain-English parsing** of usage (0-3), selector (0-1) and matching type (0-2); usage 0/1 is flagged as discouraged for SMTP (RFC 7672 wants 2 or 3)
- **DNSSEC check**: shows the resolver's AD flag and warns clearly when an answer is not DNSSEC-validated, since DANE is meaningless without it
- **Match a certificate**: paste a PEM; SHA-256 and SHA-512 of the full DER (selector 0) and of the SubjectPublicKeyInfo (selector 1) are computed with WebCrypto, using a small built-in DER parser, and compared with the TLSA records of the last lookup
- **Generator**: turns a PEM into TLSA record lines (`3 1 1` recommended)
- Dark editorial design with a light mode, self-hosted fonts, PWA, strict CSP (`script-src 'self'`)

## Privacy and limits

- Only DNS queries go to dns.google. Pasted certificates are processed in the browser and never uploaded.
- A browser cannot open TCP connections, so the page cannot fetch the certificate a server presents: paste it yourself (for example from `openssl s_client -connect host:25 -starttls smtp`).
- The DNSSEC verdict is the resolver's AD flag. The page does not validate signatures itself.
- Matching compares hashes only; it does not validate chains, names or expiry.

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

`?domain=example.com` looks up a domain's mail servers on load; `?host=example.com&port=443` looks up a host and port.

## Data sources

- [dns.google](https://developers.google.com/speed/public-dns/docs/doh): DNS-over-HTTPS for MX and TLSA lookups

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).
