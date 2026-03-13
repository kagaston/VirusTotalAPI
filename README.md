# VirusTotal API Client

CLI client for the [VirusTotal API v3](https://docs.virustotal.com/reference/overview). Scan files, submit URLs, and pull IP/domain reports from the command line.

## Features

- **File scan** -- submit a file for malware analysis
- **URL scan** -- submit a URL for scanning
- **IP report** -- retrieve threat intelligence for an IP address
- **Domain report** -- retrieve threat intelligence for a domain

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (package manager)
- [just](https://github.com/casey/just) (task runner)
- A [VirusTotal API key](https://www.virustotal.com/)

## Getting Started

1. Clone the repository:

```bash
git clone https://github.com/kagaston/VirusTotalAPI.git
cd VirusTotalAPI
```

2. Install dependencies:

```bash
just sync
```

3. Set your API key (choose one):

```bash
# Option A: environment variable
export VIRUSTOTAL_API_KEY="your-api-key-here"

# Option B: .env file in project root
echo 'VIRUSTOTAL_API_KEY=your-api-key-here' > .env
```

## Usage

```bash
# Scan a URL
uv run virustotal-api url-scan https://example.com

# Scan a file
uv run virustotal-api file-scan /path/to/file.exe

# Get an IP report
uv run virustotal-api ip-report 8.8.8.8

# Get a domain report
uv run virustotal-api domain-report example.com
```

## Development

```bash
just sync         # install dependencies
just format       # format code with ruff
just lint         # lint with ruff
just typecheck    # type check with basedpyright
just test         # run all tests
just test virustotal  # run tests for a specific package
just check        # run all CI checks (nox)
just preflight    # format + lint + typecheck + test
```

## License

MIT
