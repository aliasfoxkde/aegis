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

## GitLab CI

```yaml
security_scan:
  stage: test
  image: golang:1.21
  script:
    - curl -LO https://github.com/aliasfoxkde/aegis/releases/latest/download/aegis-linux-x86_64.tar.gz
    - tar -xzf aegis-linux-x86_64.tar.gz
    - ./aegis update
    - ./aegis --format json scan . --severity-threshold=medium --output-file aegis-results.json
  artifacts:
    reports:
      sast: aegis-results.json
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
                    ./aegis update
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
        ./aegis update
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

`docker/docker-compose.yml` wraps these in profiles (`default`, `ci`,
`test`, `daemon`); see `docker/README.md`.

## Kubernetes Admission Controller

Use Aegis as a Kubernetes admission controller to scan container images before deployment.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: aegis-scan
webhooks:
  - name: scan.aegis.dev
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
    clientConfig:
      url: https://aegis.example.com/validate
      caBundle: <base64-ca>
```

## CI/CD Best Practices

1. **Baseline**: Record a baseline of current findings once
   ```bash
   aegis --format json scan . --output-file baseline.json
   ```

2. **Baseline Gate**: Only new findings fail the build. Store the
   baseline outside the scanned tree (or add it to `.aegisignore`) so it
   does not get scanned itself:
   ```bash
   aegis scan . --baseline=../baseline.json
   ```

3. **Diff Mode**: Scan only the changed lines of a PR
   ```bash
   git diff origin/main...HEAD > pr.diff
   aegis scan . --diff=pr.diff
   ```

4. **Severity Threshold**: Start with critical only
   ```bash
   aegis scan . --severity-threshold=critical
   ```

5. **Exit Codes**: Use for pipeline failure
   - 0: no findings
   - 1: findings present (with `--baseline`, only findings that are new
     relative to the baseline)
   - 2: usage error (unknown flag or subcommand)

6. **Cache Bundles**: Don't download on every run
   ```bash
   aegis update  # weekly or on-demand
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

### Pipeline Profile (config/profiles/pipeline.json)

```json
{
  "name": "pipeline",
  "enabled_categories": ["secrets", "pii", "security-hardening", "web-security", "code-quality", "devops"],
  "strict_mode": "standard",
  "performance_mode": "optimized",
  "exit_on_findings": true,
  "max_file_size_mb": 10,
  "binary_file_detection": true,
  "gitignore_respect": true,
  "output_format": "json",
  "timeout_seconds": 300
}
```

### Production Profile

```json
{
  "name": "production",
  "enabled_categories": ["secrets", "pii", "security-hardening", "web-security"],
  "strict_mode": "strict",
  "performance_mode": "optimized",
  "exit_on_findings": true,
  "max_file_size_mb": 5,
  "binary_file_detection": true,
  "gitignore_respect": true,
  "output_format": "sarif",
  "timeout_seconds": 60
}
```
