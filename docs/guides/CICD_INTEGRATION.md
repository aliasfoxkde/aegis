# CI/CD Integration Guide

## Overview

Aegis integrates with CI/CD pipelines for early issue detection.

## GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  aegis-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Aegis
        run: |
          curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
          tar -xzf aegis-linux-x86_64.tar.gz
          sudo mv aegis /usr/local/bin/

      - name: Run Scan
        run: aegis --format json scan . --severity-threshold=medium --output-file aegis-results.json

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: aegis-results
          path: aegis-results.json

      - name: Fail on Critical
        if: always()
        run: |
          if grep -q '"severity": "critical"' aegis-results.json; then
            echo "Critical findings detected!"
            exit 1
          fi
```

`aegis --format json scan .` writes pretty-printed JSON, so the severity
key is followed by a space. Because the scan already exits non-zero when
it produces findings, the "Fail on Critical" step is only needed when you
want to gate on one severity rather than on any finding.

## GitHub Code Scanning (SARIF)

To publish Aegis findings in the repository's **Security → Code scanning**
view, emit SARIF and upload it with the GitHub code-scanning action. The
workflow needs `security-events: write`; the scan step keeps Aegis's exit
status so findings at or above the selected threshold can fail the job.

```yaml
name: Aegis security scan

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  aegis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Aegis
        run: |
          curl -fsSLO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
          tar -xzf aegis-linux-x86_64.tar.gz
          sudo install -m 0755 aegis /usr/local/bin/aegis

      - name: Scan and write SARIF
        run: aegis --format sarif scan . --severity-threshold high --output-file aegis-results.sarif

      - name: Upload SARIF to GitHub code scanning
        if: always() && hashFiles('aegis-results.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: aegis-results.sarif
          category: aegis
```

The upload step is conditional so a missing report does not cause a second
failure that hides the original scan error. Confirm that code scanning is
available for the repository and that the workflow token has the permissions
shown above. For artifact retention without code-scanning integration, use
the JSON artifact example below.

## GitLab CI

```yaml
security_scan:
  stage: test
  image: golang:1.21
  script:
    - curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
    - tar -xzf aegis-linux-x86_64.tar.gz
    - ./aegis --format json scan . --severity-threshold=medium --output-file aegis-results.json
  artifacts:
    paths:
      - aegis-results.json
    when: always
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Install') {
            steps {
                sh '''
                    curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
                    tar -xzf aegis-linux-x86_64.tar.gz
                '''
            }
        }
        stage('Security Scan') {
            steps {
                sh './aegis --format json scan . --severity-threshold=medium --output-file aegis-results.json'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'aegis-results.json', allowEmptyArchive: true
        }
    }
}
```

## Azure DevOps

```yaml
trigger:
  - main
  - develop

pool:
  vmImage: ubuntu-latest

steps:
  - task: Bash@3
    displayName: 'Aegis Security Scan'
    inputs:
      script: |
        curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
        tar -xzf aegis-linux-x86_64.tar.gz
        ./aegis --format json scan . --severity-threshold=medium --output-file aegis-results.json
      cwd: '$(System.DefaultWorkingDirectory)'

  - task: PublishBuildArtifacts@1
    inputs:
      pathtoPublish: 'aegis-results.json'
```

## Pre-commit Hook

Install as pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: aegis-scan
        name: Aegis Security Scan
        entry: aegis scan . --staged
        args: ['--severity-threshold=high', '--quiet']
        language: system
        pass_filenames: false
        always_run: true
```

`--staged` reads the git index, so the hook scans exactly what the
commit would contain — including hunks staged with `git add -p` — not
whatever currently sits in the working tree. Nothing staged is a clean
pass, so the hook never blocks commits that touch no code.

## Docker Scan

Build the image locally first — no image is published to a registry:

```bash
docker build -t aegis:latest -f docker/Dockerfile .

# Scan the current directory
docker run --rm -v $(pwd):/workspace aegis:latest scan /workspace

# Scan with SARIF output (--format precedes the subcommand)
docker run --rm -v $(pwd):/workspace aegis:latest \
  --format sarif scan /workspace --output-file /workspace/aegis-results.sarif
```

`docker/docker-compose.yml` wraps these in profiles (`default`,
`json`, `ci`); see `docker/README.md`.

## Kubernetes

There is no admission-controller integration: Aegis is a filesystem
scanner with no HTTP server, so it cannot receive webhook callbacks.
Cluster usage is the scheduled-scan CronJob in `kubernetes/cronjob.yaml`
(mount the workspace, scan it, SARIF report next to the source).

## CI/CD Best Practices

1. **Baseline**: Record a baseline of current findings once
   ```bash
   aegis --format json scan . --output-file baseline.json
   ```

2. **Baseline Gate**: Only new findings fail the build. The
   conventional home for the baseline is `.aegis/baseline.json` inside
   the scanned tree — the `.aegis/` state directory is always excluded
   from scans, so the artifact can quote recorded findings without ever
   being re-scanned itself:
   ```bash
   aegis scan . --baseline .aegis/baseline.json
   ```

3. **Diff Mode**: Scan only the changed lines of a PR
   ```bash
   git diff origin/main...HEAD > pr.diff
   aegis scan . --diff pr.diff
   ```

4. **Severity Threshold**: Start with critical only
   ```bash
   aegis scan . --severity-threshold=critical
   ```

5. **Exit Codes**: Use for pipeline failure (the full table lives in
   [docs/guides/CLI.md](CLI.md#exit-codes))
   - 0: complete scan, no findings at or above the threshold (`info`
     observations never trip the exit code)
   - 1: complete scan with findings (with `--baseline`, only findings
     that are new relative to the baseline); also used when a scan fails
     before producing a receipt (for example an unreadable scan root or
     an invalid `.aegis.yml`)
   - 2: usage error (unknown flag or subcommand)
   - 3: incomplete scan: the receipt does not certify that every required
     inspection completed (`ScanReceipt::allows_safe()` is false — a
     required file could not be read, was skipped by the size limit, or
     had no analyzer such as a binary). Reported findings stay in the
     output and receipt, but an unproven inspection never passes as
     clean, so gate on `3` even when zero findings are reported. The
     usual trigger is a binary or otherwise unsupported asset: Aegis
     does not scan binaries, so one unignored binary in the scanned
     tree fails the receipt closed. When such an asset is intentional
     and the integration runs a directory scan, add a matching
     gitignore-style rule to `.aegisignore` in the scan root — excluded
     paths are not required inspections, so they cannot force exit 3.
     `.aegisignore` is loaded only for directory scans: a single-file
     scan (`--file`, or a path naming a file) never reads it, so there
     an unsupported file fails closed regardless — filter it out of the
     integration's file list or scan its directory instead. Full syntax:
     [docs/guides/CONFIGURATION.md](CONFIGURATION.md#ignoring-files)

6. **Pin the Version**: Patterns ship inside the binary, so pinning the
   release pins the detection set. Use a versioned download URL instead
   of `releases/latest` so a new release can never change your gate
   semantics mid-stream:
   ```bash
   curl -LO https://github.com/aliasfoxkde/aegis/releases/download/v0.6.3/aegis-linux-x86_64.tar.gz
   ```

## SARIF Output

Upload SARIF to GitHub Security tab:

```yaml
- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aegis-results.sarif
```

---

## Configuration Profiles

For CI, the built-in `pipeline` and `production` profiles are the usual
starting points:

```bash
aegis --config pipeline scan .
```

The canonical JSON lives in
[`config/profiles/`](../../config/profiles/) and is kept in sync with
the built-ins by a test; see
[Configuration](CONFIGURATION.md#profiles) for the full field
reference and the shipped presets.
