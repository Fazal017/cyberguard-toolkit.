# CyberGuard Toolkit

A small, defensive Python toolkit that helps website owners review basic web security settings.

## Current status

This is an initial public-release version. It checks one website URL supplied by the user and produces a concise report covering:
- Common HTTP security headers
- TLS certificate expiry
- DNS resolution

It does **not** exploit vulnerabilities, brute-force services, crawl websites, or scan IP ranges.

## Requirements

- Python 3.10 or newer
- No third-party Python packages required

## Run

```bash
python -m cyberguard https://example.com
```

Or:

```bash
python -m cyberguard https://example.com --json report.json
```

Only test websites you own or have explicit permission to assess. The tool makes a basic HTTP request and a TLS connection to the supplied host.

## Checks performed

### HTTP headers
Looks for:
- Strict-Transport-Security
- Content-Security-Policy
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-Frame-Options

A missing header is a hardening recommendation, not proof that a site is vulnerable. Some sites may enforce equivalent protections through other mechanisms.

### TLS certificate
Reports the certificate's expiry date and the number of days remaining. Certificate verification is enabled.

### DNS
Reports whether the hostname resolves to an IP address. DNS resolution alone does not establish that a domain is secure.

## Limitations

This is an educational baseline checker, not a penetration-testing tool, compliance audit, or guarantee of security. Results should be reviewed by a qualified security professional before making important decisions.

## Roadmap

- Add unit tests for report formatting and URL validation
- Add optional CSV export
- Improve internationalized-domain and proxy support
- Add configurable checks with clear explanations

## Contributing

Issues and pull requests are welcome. Please include reproducible steps and avoid sharing secrets, private URLs, or sensitive scan results.

## License

MIT. See [LICENSE](LICENSE).
