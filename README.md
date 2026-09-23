# Web-Security-Information-Scanner
A Python-based website security scanner that checks authorised websites for common security misconfigurations, and vulnerabilities.

## Requirements
Set up a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Then:

```bash
pip3 install -r requirements.txt
```

Run with:

```bash
python3 main.py
```

## Features

- Security header analysis
- TLS/SSL certificate information
- Cookie security checks
- HTTP method detection
- CORS configuration checks
- Mixed content detection
- Insecure form detection
- Password autocomplete checks
- External JavaScript detection
- Subresource Integrity (SRI) checks
- HTML comment scanning
- Sensitive file detection
- Directory listing detection
- `robots.txt` analysis
- `security.txt` detection
- DNS information gathering
- Email address discovery
- Web technology detection
- Page information and metadata extraction
- Access key detection
- Basic form and input analysis
- HTTP response analysis
- Colour-coded terminal output

## Colour codes
- Red = May be bad
- Orange = Point of interest
- Green = Success

## Planned Features

- Better framework/library detection
- Version mapping with CVEs
- Structured layout