# trivy-converter

A small, dependency-free command-line tool written in Go that converts security scan reports from other tools into the **Trivy JSON report format** (`SchemaVersion: 2`), so they can be consumed by anything that already understands Trivy output (dashboards, report generators, CI gates, defect trackers, etc.).

## What it does

| Input tool | Input format | What is converted |
|------------|--------------|-------------------|
| [Grype](https://github.com/anchore/grype) | JSON (`grype -o json`) | Vulnerability matches |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | JSON / NDJSON (`trufflehog --json`) | Secret findings |

The input format is **auto-detected**:

- **Grype** – a single JSON object with top-level `matches` and `descriptor` keys.
- **TruffleHog** – one or more concatenated JSON objects (one per line, or multi-line) containing `DetectorName`.

You can override detection with `--format`.

### Grype → Trivy

- Matches are grouped into one Trivy `Result` per ecosystem (e.g. `Java/jar`, `Python/pip`, `Node.js/npm`, `Go/gomod`, `Ruby/gemspec`, `.NET/dotnet-core`, `Rust/cargo`, `OS Packages/rpm|dpkg`).
- Each result contains a de-duplicated `Packages` list (with PURL and UID) and the `Vulnerabilities` list.
- Fields mapped: vulnerability ID, related IDs (as `VendorIDs`, e.g. GHSA aliases), installed / fixed version, fix state (`fixed`, `affected`, `will_not_fix`, `end_of_life`, `unknown`), severity, description, references, CWE IDs, CVSS v2/v3 vectors and scores, vendor severity, data source and primary URL (`avd.aquasec.com` when an NVD link is present).
- Java packages are named `groupId:artifactId`.
- The report timestamp is taken from the Grype descriptor; `ArtifactName` / `ArtifactType` come from the Grype `source`.

### TruffleHog → Trivy

- Findings are grouped per file into Trivy `Result`s of class `secret`.
- Works with both `Filesystem` and `Git` source metadata (Windows paths are normalized to `/`).
- Severity: `CRITICAL` if the secret was **verified**, otherwise `HIGH`.
- The `RuleID` is the lower-cased, dash-separated detector name.
- **Secret values are redacted**: only the first and last 4 characters of the raw value are kept in `Match`, the rest is replaced with `*`.

> Note: the output declares Trivy version `0.70.0` and a randomly generated `ReportID`. The converter only reshapes data; it does not run Trivy or re-scan anything.

## Requirements

- [Go](https://go.dev/dl/) 1.18 or newer (only the standard library is used).

The repository contains a single source file, `main.go`. If there is no `go.mod` yet, create one once:

```sh
go mod init trivy-converter
```

## Building

### Windows

PowerShell or Command Prompt:

```bat
compile.bat
```

or manually:

```powershell
go build -o trivy-converter.exe .
```

To build **and** run smoke tests (optionally with your own sample reports):

```powershell
.\build_and_test.ps1 -GrypeInput ptof_grype.json -SecretsInput ptof_secrets.json
# build only:
.\build_and_test.ps1 -SkipTests
```

### Linux

```sh
go build -o trivy-converter .
chmod +x trivy-converter   # normally already set by go build
```

### macOS

```sh
go build -o trivy-converter .
```

### Cross-compiling

Go can build for any platform from any platform by setting `GOOS` / `GOARCH`.

**From Linux / macOS (bash/zsh):**

```sh
GOOS=windows GOARCH=amd64 go build -o trivy-converter.exe .
GOOS=linux   GOARCH=amd64 go build -o trivy-converter-linux-amd64 .
GOOS=linux   GOARCH=arm64 go build -o trivy-converter-linux-arm64 .
GOOS=darwin  GOARCH=amd64 go build -o trivy-converter-macos-intel .
GOOS=darwin  GOARCH=arm64 go build -o trivy-converter-macos-apple-silicon .
```

**From Windows (PowerShell):**

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o trivy-converter-linux-amd64 .
$env:GOOS="darwin"; $env:GOARCH="arm64"; go build -o trivy-converter-macos-apple-silicon .
Remove-Item Env:GOOS, Env:GOARCH   # restore native builds
```

## Usage

```
trivy-converter --input <file> [--output <file>] [--format grype|trufflehog] [--pretty=false]
trivy-converter <file>            # short form, positional argument
```

| Flag | Description | Default |
|------|-------------|---------|
| `--input` | Input file (Grype JSON or TruffleHog JSON/NDJSON) | – (or first positional argument) |
| `--output` | Output file | stdout |
| `--format` | Force the input format: `grype` or `trufflehog` | auto-detect |
| `--pretty` | Indent the output JSON (`--pretty=false` for compact output) | `true` |

Progress and errors are written to **stderr**, the JSON report to **stdout** (or to `--output`), so redirection is safe. The exit code is `0` on success and `1` on any error.

### Generating the input reports

```sh
# Vulnerabilities
grype dir:. -o json > grype.json
grype myimage:latest -o json > grype.json

# Secrets
trufflehog filesystem . --json > secrets.ndjson
trufflehog git file://. --json > secrets.ndjson
```

### Windows (PowerShell / cmd)

```powershell
.\trivy-converter.exe --input grype.json --output trivy-vulns.json
.\trivy-converter.exe --input secrets.ndjson --format trufflehog --output trivy-secrets.json
.\trivy-converter.exe grype.json > trivy.json
```

### Linux

```sh
./trivy-converter --input grype.json --output trivy-vulns.json
./trivy-converter --input secrets.ndjson --format trufflehog --output trivy-secrets.json
./trivy-converter grype.json > trivy.json

# optional: install system-wide
sudo install -m 0755 trivy-converter /usr/local/bin/
```

### macOS

```sh
./trivy-converter --input grype.json --output trivy-vulns.json
./trivy-converter --input secrets.ndjson --format trufflehog --output trivy-secrets.json
./trivy-converter grype.json > trivy.json

# optional: install system-wide
sudo install -m 0755 trivy-converter /usr/local/bin/
```

If you copy a binary downloaded or cross-compiled on another machine, macOS Gatekeeper may block it. Remove the quarantine flag with:

```sh
xattr -d com.apple.quarantine ./trivy-converter
```

### Using the result

The output can be fed to any tool that reads Trivy JSON, for example:

```sh
trivy convert --format table trivy-vulns.json     # re-render with Trivy itself
```

## Limitations

- Only Grype and TruffleHog are supported as inputs.
- Package `Layer`, `Locations` and `Misconfigurations` are not produced.
- A TruffleHog file with no findings is reported as an error.
- The CLI messages are currently in Italian.
