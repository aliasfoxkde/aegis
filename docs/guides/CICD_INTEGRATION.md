# CI/CD Integration Guide

## Overview

Atheon-Enhanced integrates with CI/CD pipelines for early issue detection.

## GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  atheon-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Atheon
        run: |
          curl -sSL https://get.atheon.dev | sh
          atheon update
      
      - name: Run Scan
        run: atheon scan . --severity-threshold=medium --json > atheon-results.json
      
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: atheon-results
          path: atheon-results.json
      
      - name: Fail on Critical
        if: always()
        run: |
          if grep -q '"severity":"critical"' atheon-results.json; then
            echo "Critical findings detected!"
            exit 1
          fi
```

## GitLab CI

```yaml
security_scan:
  stage: test
  image: golang:1.21  # or atheon-container
  script:
    - wget https://get.atheon.dev -O atheon
    - chmod +x atheon
    - ./atheon update
    - ./atheon scan . --json --severity-threshold=medium > atheon-results.json
  artifacts:
    reports:
      sast: atheon-results.json
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
        stage('Security Scan') {
            steps {
                sh '''
                    curl -sSL https://get.atheon.dev -o atheon
                    chmod +x atheon
                    ./atheon update
                    ./atheon scan . --json --severity-threshold=medium > atheon-results.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'atheon-results.json'
                    insertText: find pattern: '"severity":"critical"', text: readFile('atheon-results.json')
                }
            }
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
    displayName: 'Atheon Security Scan'
    inputs:
      script: |
        curl -sSL https://get.atheon.dev -o atheon
        chmod +x atheon
        ./atheon update
        ./atheon scan . --json --severity-threshold=medium > atheon-results.json
      cwd: '$(System.DefaultWorkingDirectory)'
  
  - task: PublishBuildArtifacts@1
    inputs:
      pathtoPublish: 'atheon-results.json'
  
  - task: VulnerabilityCheck@0
    inputs:
      artifacts: 'atheon-results.json'
      severityThreshold: 'Medium'
```

## Pre-commit Hook

Install as pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: atheon-scan
        name: Atheon Security Scan
        entry: atheon scan
        args: ['--severity-threshold=high', '--quiet']
        language: system
        files: .
```

## Docker Scan

```bash
# Scan Docker image
docker run --rm -v $(pwd):/src atheon scan /src

# Scan container filesystem
docker run --rm -v /var/lib/docker/overlay2:/mnt ubuntu atheon scan /mnt
```

## Kubernetes Admission Controller

Use Atheon as a Kubernetes admission controller to scan container images before deployment.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: atheon-scan
webhooks:
  - name: scan.atheon.dev
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
    clientConfig:
      url: https://atheon.example.com/validate
      caBundle: <base64-ca>
```

## CI/CD Best Practices

1. **Baseline**: Create a baseline of current findings
   ```bash
   atheon scan . --json > baseline.json
   ```

2. **Diff Mode**: Only report new findings
   ```bash
   atheon scan . --diff=baseline.json --json
   ```

3. **Severity Threshold**: Start with critical only
   ```bash
   atheon scan . --severity-threshold=critical
   ```

4. **Exit Codes**: Use for pipeline failure
   - 0: No findings or only low severity
   - 1: Findings at or above threshold

5. **Cache Bundles**: Don't download on every run
   ```bash
   atheon update  # weekly or on-demand
   ```

## SARIF Output

Upload SARIF to GitHub Security tab:

```yaml
- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: atheon-results.sarif
```

---

## Configuration Profiles

### Pipeline Profile (config/profiles/pipeline.json)

```json
{
  "name": "pipeline",
  "enabled_categories": ["secrets", "pii", "security", "code-quality", "devops"],
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
  "enabled_categories": ["secrets", "pii", "security"],
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
