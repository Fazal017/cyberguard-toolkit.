import argparse
import json
from pathlib import Path
from cyberguard.checker import check_site


def main():
    parser = argparse.ArgumentParser(
        description="Run a basic defensive security review of one website."
    )
    parser.add_argument("url", help="Website URL, for example https://example.com")
    parser.add_argument("--json", dest="json_path", help="Optional path to save JSON report")
    args = parser.parse_args()

    report = check_site(args.url)
    print(f"CyberGuard Toolkit report for: {report['url']}")
    print("=" * 58)

    print("\nHTTP security headers")
    for item in report["http_headers"]:
        status = "Present" if item["present"] else "Missing"
        print(f"- {item['header']}: {status} | {item['note']}")

    print("\nTLS certificate")
    tls = report["tls"]
    if tls.get("error"):
        print(f"- Could not inspect certificate: {tls['error']}")
    else:
        print(f"- Expires: {tls['expires_at']}")
        print(f"- Days remaining: {tls['days_remaining']}")

    print("\nDNS")
    dns = report["dns"]
    if dns.get("error"):
        print(f"- Resolution issue: {dns['error']}")
    else:
        print(f"- Resolved addresses: {', '.join(dns['addresses'])}")

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report saved to: {args.json_path}")


if __name__ == "__main__":
    main()
