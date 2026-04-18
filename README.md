# Security Audit Platform

Automated security scanning, vulnerability detection & compliance checking.

## Features

- **Port scanning** - Detect open ports and dangerous services
- **SSL/TLS analysis** - Check certificate validity and TLS versions
- **Security headers** - Verify HTTP security headers
- **Vulnerability detection** - SQLi, XSS, dependency checks
- **Compliance checking** - OWASP Top 10, PCI DSS, SOC2
- **Multiple formats** - JSON, HTML, Markdown reports

## Installation

```bash
pip install -e .
```

## Quick Start

```python
import asyncio
from security_audit import SecurityScanner, ScanTarget

async def main():
    scanner = SecurityScanner(timeout=30)
    
    target = ScanTarget(domain="example.com", port=443)
    
    # Run full scan
    results = await scanner.run_full_scan(target)
    
    # Generate report
    from security_audit.reporter import ReportGenerator
    reporter = ReportGenerator(results)
    files = reporter.save("./reports", formats=["json", "html"])
    
    print(f"Reports saved: {files}")

asyncio.run(main())
```

## API

### Scanner

```python
scanner = SecurityScanner(timeout=30, max_concurrent=10)

# Individual scans
port_result = await scanner.scan_ports(target, [80, 443, 8080])
ssl_result = await scanner.scan_ssl(target)
header_result = await scanner.scan_headers(target)

# Close session
await scanner.close()
```

### Compliance

```python
from security_audit.detectors import ComplianceChecker

checker = ComplianceChecker(standard="OWASP_TOP_10")
compliance = checker.check(results)
print(f"Score: {compliance['score']}/100")
```

## License

MIT