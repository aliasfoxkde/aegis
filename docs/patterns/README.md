# Detection Patterns

Aegis ships **638 detection patterns** across **33 categories**.
This document is generated from the pattern source in
`crates/aegis-patterns/src/`; regenerate with:

```bash
cargo run -p aegis-patterns --example generate_docs
```

A freshness test (`registry_hygiene.rs`) fails CI when this file drifts
from the shipped patterns.

## Pattern Selection

Each pattern can carry two optional scoping fields:

- `exclude` — a regex matched against the finding's text; a hit suppresses
  the finding (used to exempt documentation examples and safe idioms).
- `file_extensions` — the pattern only runs on files with a listed
  extension. An empty list means the pattern applies everywhere.

## Categories

| Category | Patterns | Description |
|----------|----------|-------------|

| [accessibility](#accessibility) | 28 | WCAG 2.x success criteria for markup, media, and styles |
| [ai-detection](#aidetection) | 24 | Heuristics that flag likely AI-generated code |
| [ai-safety](#aisafety) | 25 | Agentic and LLM application safety checks |
| [api-integration](#apiintegration) | 9 | HTTP client and webhook integration mistakes |
| [arm](#arm) | 2 | Azure Resource Manager template issues |
| [cloud-native](#cloudnative) | 38 | Cloud-native build and runtime practices |
| [cloudformation](#cloudformation) | 3 | AWS CloudFormation template issues |
| [code-quality](#codequality) | 15 | Language anti-patterns and dangerous constructs |
| [compliance](#compliance) | 33 | Regulatory frameworks: GDPR, HIPAA, PCI-DSS, SOC 2 |
| [container](#container) | 4 | Container build and runtime hardening |
| [data-visualization](#datavisualization) | 5 | Charting and visualization pitfalls |
| [devops](#devops) | 15 | CI/CD pipeline and deployment checks |
| [finance](#finance) | 6 | Financial data handling rules |
| [frameworks](#frameworks) | 31 | Web framework-specific issues |
| [git-hygiene](#githygiene) | 28 | Repository hygiene: artifacts, debug files, history |
| [git-ops](#gitops) | 3 | GitOps workflow and manifest checks |
| [graphql](#graphql) | 4 | GraphQL API security and usage |
| [healthcare](#healthcare) | 7 | Clinical data and HIPAA-adjacent rules |
| [infrastructure](#infrastructure) | 55 | Infrastructure as code security |
| [kubernetes](#kubernetes) | 11 | Kubernetes manifest hardening |
| [llm-guardrails](#llmguardrails) | 25 | Prompt-injection and LLM guardrail checks |
| [metadata](#metadata) | 4 | Metadata and editor configuration leaks |
| [performance](#performance) | 22 | Performance anti-patterns |
| [pii](#pii) | 39 | Personal data: emails, phones, national IDs |
| [pwa](#pwa) | 5 | Progressive web app checks |
| [secrets](#secrets) | 41 | Credentials, API keys, and tokens |
| [security-hardening](#securityhardening) | 33 | General hardening practices |
| [shift-left](#shiftleft) | 20 | Early-lifecycle security practices |
| [supply-chain](#supplychain) | 35 | Dependency and artifact supply-chain rules |
| [terraform](#terraform) | 7 | HashiCorp Terraform issues |
| [typescript](#typescript) | 13 | TypeScript and typed-JavaScript rules |
| [web-development](#webdevelopment) | 11 | General web development checks |
| [web-security](#websecurity) | 37 | XSS, injection, CORS, and SSRF |

---

## accessibility

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `accesskey-usage` | low | high | accesskey attribute may conflict with assistive tech shortcuts |
| `aria-live-off` | low | high | Live region explicitly disabled with aria-live=off |
| `aria-role-invalid` | medium | high | Invalid ARIA role value (not a defined role) |
| `audio-missing-transcript` | low | low | Audio element present - verify a transcript is provided |
| `autocomplete-missing` | low | medium | Text input missing autocomplete attribute |
| `autoplay-media` | medium | medium | Media set to autoplay (must be muted or user-controlled) |
| `blinking-content` | medium | medium | Blinking content may cause accessibility issues |
| `click-without-keyboard` | high | medium | Click handler on an element that is not keyboard focusable |
| `empty-button` | medium | high | Button has no text content or accessible name |
| `empty-label` | medium | high | Label element has no text content |
| `empty-link-text` | medium | high | Anchor has no link text or accessible name |
| `font-size-below-12px` | low | medium | Font size below 12px/pt detected |
| `iframe-missing-title` | medium | high | Iframe missing title attribute |
| `invalid-heading-level` | low | high | Heading level h6 or higher does not exist in HTML |
| `marquee-element` | high | high | Deprecated marquee element used |
| `missing-alt-text` | medium | high | Image missing alt attribute |
| `missing-focus-indicator` | medium | medium | Focus outline removed without a visible replacement |
| `missing-form-label` | medium | medium | Form input missing an associated label |
| `missing-lang-attribute` | medium | high | HTML element missing lang attribute |
| `missing-main-landmark` | low | medium | Page body has no main landmark |
| `missing-meta-viewport` | medium | high | Viewport meta disables user zoom (user-scalable=no) |
| `missing-skip-link` | low | medium | Page body has no skip-to-content link |
| `missing-table-headers` | medium | medium | Table has no header cells (<th>) |
| `missing-title` | medium | high | Document head missing a <title> element |
| `positive-tabindex` | medium | high | Positive tabindex overrides natural focus order |
| `single-character-heading` | low | medium | Heading contains a single character (likely decorative misuse) |
| `target-blank-unlabeled` | low | medium | Link opens in a new window without an accessible warning |
| `video-missing-captions` | medium | medium | Video element missing a captions track |

## ai-detection

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `ai-detection-empty-catch-block` | low | high | Empty catch block detected |
| `ai-generated-comment` | low | medium | AI-generated code comment detected |
| `ai-generated-marker` | low | medium | AI generation marker detected |
| `ai-header-comment` | low | medium | AI-style header comment with permissions |
| `ai-magic-number` | low | low | Magic number without constant declaration |
| `ai-overexplanation` | low | low | AI overexplanation pattern detected |
| `ai-placeholder` | low | medium | AI placeholder text detected |
| `ai-repetitive-structure` | low | low | Highly repetitive code structure detected |
| `ai-template-marker` | low | medium | AI template marker detected |
| `chatgpt-conversation` | low | low | ChatGPT prompt pattern detected |
| `comment-block-repeat` | low | low | Excessive comment blocks detected |
| `console-log-debug` | low | low | Console logging statements detected |
| `function-comment-every` | low | low | Every function has descriptive comments (AI style) |
| `function-name-verbose` | low | low | Verbose function naming detected |
| `generic-variable-names` | low | low | Generic variable names detected (common in AI code) |
| `import-bulk` | low | medium | Bulk import detected (common in AI-generated code) |
| `markdown-code-fence` | low | low | Markdown code fence detected |
| `openai-format` | low | low | Common AI assistant phrasing detected |
| `response-format-json` | low | medium | Generic JSON response format pattern |
| `semicolon-everywhere` | low | low | Excessive semicolons in JavaScript/TypeScript |
| `superfluous-type-annotation` | low | low | Redundant type annotation (TypeScript) |
| `todo-still-present` | low | low | TODO/FIXME comment still present in code |
| `try-catch-bulk` | low | low | Verbose try-catch blocks detected |
| `very-long-line` | low | low | Very long line detected (common in AI output) |

## ai-safety

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `adversarial-testing` | medium | high | Adversarial testing reference detected |
| `ai-bias-report` | medium | high | AI bias or fairness assessment reference |
| `ai-incident-response` | medium | high | AI incident response reference detected |
| `attention-visualization` | low | high | Model visualization reference detected |
| `bias-in-training` | medium | medium | Potential bias in training data reference |
| `consent-for-training` | high | high | Consent for data training reference detected |
| `constitutional-ai` | low | high | Constitutional AI reference detected |
| `data-augmentation` | low | high | Data augmentation technique reference |
| `evaluation-benchmark` | low | high | AI evaluation benchmark reference |
| `hallucination-risk` | medium | medium | Potential hallucination risk detected |
| `human-approval-required` | medium | high | Human approval requirement detected |
| `human-in-the-loop` | medium | high | Human-in-the-loop reference detected |
| `interpretability-tool` | low | high | Interpretability tool reference detected |
| `mesa-optimization` | high | low | Potential mesa-optimization risk detected |
| `model-card-missing` | low | high | Model card or documentation reference |
| `model-rollback` | medium | high | Model rollback capability detected |
| `model-version-tracking` | low | high | Model version tracking reference |
| `noise-injection` | low | high | Noise injection technique reference |
| `prompt-injection` | high | medium | Potential prompt injection detected |
| `reward-hacking-risk` | high | medium | Potential reward hacking risk detected |
| `rlhf-reference` | low | high | RLHF technique reference detected |
| `rlhf-reward-model` | medium | high | Reward model training reference detected |
| `system-prompt-leak` | medium | low | Potential system prompt reference detected |
| `training-data-audit` | medium | high | Training data audit reference detected |
| `unsafe-model-output` | high | high | Unsafe model output detected |

## api-integration

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `api-client-no-timeout` | low | medium | HTTP client created without a timeout |
| `api-key-in-query-param` | high | high | Credential passed in a URL query string; use an Authorization header instead |
| `api-polling-loop` | low | medium | Fixed-interval polling loop with fetch; prefer event-driven updates or exponential backoff |
| `api-response-status-unchecked` | low | medium | Fetch response body parsed without a visible status check |
| `bearer-token-logged` | high | high | Authorization token passed to a logging call |
| `cors-credentials-wildcard` | high | medium | CORS configured with wildcard origin and credentials together |
| `hardcoded-internal-endpoint` | low | medium | Hardcoded localhost/internal endpoint; move base URLs to configuration |
| `ssl-verification-disabled` | high | high | TLS certificate verification disabled for an API client |
| `webhook-signature-unchecked` | medium | medium | Webhook route registered without a visible signature check |

## arm

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `arm-azure-sql-no-firewall` | high | high | Detects Azure ARM template SQL server without proper firewall rules |
| `arm-azure-storage-enable-https` | high | high | Detects Azure ARM template storage account with HTTPS traffic disabled |

## cloud-native

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `api-gateway` | low | high | API Gateway detected |
| `aws-ecs-task` | low | high | AWS ECS task definition detected |
| `aws-eks-cluster` | low | high | AWS EKS cluster detected |
| `aws-lambda-function` | low | medium | AWS Lambda function reference detected |
| `aws-sam-template` | low | high | AWS SAM template detected |
| `azure-aks-cluster` | low | high | Azure AKS cluster detected |
| `azure-functions` | low | high | Azure Functions detected |
| `circuit-breaker` | medium | high | Circuit breaker pattern detected |
| `cloud-native-kubernetes-secret` | high | high | Kubernetes Secret resource detected |
| `cloud-native-kubernetes-service` | low | high | Kubernetes Service detected |
| `consul-service` | low | medium | Consul service definition detected |
| `container-capabilities` | high | high | Dangerous container capability added |
| `container-liveness-probe` | medium | high | Container liveness probe configured |
| `container-privileged` | critical | high | Privileged container detected |
| `container-readiness-probe` | medium | high | Container readiness probe configured |
| `container-resources` | low | high | Container resource limits configured |
| `container-security-context` | medium | high | Container security context configured |
| `dockerfile-exposed` | medium | high | Potentially sensitive port exposed in Dockerfile |
| `elasticsearch-config` | low | high | Elasticsearch configuration detected |
| `etcd-service` | low | medium | etcd service configuration detected |
| `fluentd-config` | low | high | Fluentd logging configuration detected |
| `gcp-gke-cluster` | low | high | GCP GKE cluster detected |
| `google-cloud-function` | low | high | Google Cloud Function detected |
| `grafana-dashboard` | low | high | Grafana dashboard detected |
| `helm-release` | low | high | Helm release detected |
| `helm-repo` | low | high | Helm repository reference detected |
| `istio-destinationrule` | low | high | Istio DestinationRule detected |
| `istio-peer-authentication` | medium | high | Istio PeerAuthentication detected |
| `istio-virtualservice` | low | high | Istio VirtualService detected |
| `jaeger-tracing` | low | high | Distributed tracing configuration detected |
| `kubernetes-endpoints` | low | high | Kubernetes Endpoints detected |
| `linkerd-service-profile` | low | high | Linkerd ServiceProfile detected |
| `network-policy-egress` | medium | high | Network policy egress rule detected |
| `network-policy-ingress` | medium | high | Network policy ingress rule detected |
| `pod-security-policy` | medium | high | PodSecurityPolicy detected |
| `prometheus-metrics` | low | high | Prometheus metrics endpoint detected |
| `retry-policy` | low | high | Retry policy detected |
| `timeout-configuration` | low | high | Timeout configuration detected |

## cloudformation

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `cloudformation-iam-lambda-assume-role` | medium | high | Detects CloudFormation IAM or Lambda trust policy with wildcard principal |
| `cloudformation-s3-no-encryption` | high | high | Detects CloudFormation S3 bucket without server-side encryption |
| `cloudformation-s3-public-access` | critical | high | Detects CloudFormation S3 bucket with public access enabled |

## code-quality

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `code-quality-eval-usage` | high | high | Use of eval() detected |
| `commented-code` | low | medium | Commented-out code detected |
| `console-log` | low | high | Console logging statement detected |
| `debugger-statement` | medium | high | Debugger statement detected |
| `double-negation` | low | high | Double negation (!!) detected |
| `empty-catch-block` | medium | high | Empty catch block detected |
| `excess-line-length` | low | high | Excessively long line detected (>200 characters) |
| `hardcoded-date` | low | high | Hardcoded date detected |
| `loose-equality` | low | high | Loose equality comparison ('=='); prefer strict equality ('===') |
| `magic-number` | low | medium | Magic number detected |
| `nested-callbacks` | medium | medium | Deeply nested callbacks detected (callback hell) |
| `print-statement` | low | high | Print statement detected |
| `todo-comment` | low | high | TODO/FIXME comment detected |
| `var-declaration` | low | high | Use of 'var' instead of 'let'/'const' (ES6+) |
| `with-statement` | medium | high | Use of with statement detected |

## compliance

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `ccpa-consumer-rights` | low | high | CCPA consumer rights reference detected |
| `ccpa-reference` | low | medium | CCPA reference detected |
| `cobit` | low | medium | COBIT reference detected |
| `coppa` | high | high | COPPA reference detected |
| `coso` | low | medium | COSO framework reference detected |
| `data-residency` | medium | high | Data residency requirement reference detected |
| `data-retention` | medium | high | Data retention policy reference detected |
| `fedramp` | medium | high | FedRAMP reference detected |
| `ferpa` | medium | high | FERPA reference detected |
| `gdpr-article-17` | low | high | GDPR Article 17 (Right to Erasure) reference detected |
| `gdpr-article-25` | low | high | GDPR Article 25 (Data Protection by Design) reference detected |
| `gdpr-article-32` | medium | high | GDPR Article 32 (Security of Processing) reference detected |
| `gdpr-reference` | low | medium | GDPR reference detected |
| `glba` | medium | high | GLBA (Gramm-Leach-Bliley Act) reference detected |
| `hipaa-phi` | high | high | HIPAA Protected Health Information (PHI) reference detected |
| `hipaa-reference` | low | medium | HIPAA reference detected |
| `hipaa-safeguards` | medium | high | HIPAA safeguards reference detected |
| `hitrust` | medium | high | HITRUST reference detected |
| `iso-27001` | low | high | ISO 27001 reference detected |
| `iso-27002` | low | high | ISO 27002 reference detected |
| `iso-9001` | low | medium | ISO 9001 reference detected |
| `lgpd` | low | medium | LGPD (Brazilian GDPR) reference detected |
| `nist-800-190` | medium | high | NIST SP 800-190 (Container Security) reference detected |
| `nist-800-53` | medium | high | NIST SP 800-53 reference detected |
| `nist-framework` | low | medium | NIST Cybersecurity Framework reference detected |
| `pa-dss` | high | high | PA-DSS reference detected |
| `pci-cardholder-data` | high | high | PCI cardholder data reference detected |
| `pci-dss` | medium | high | PCI DSS reference detected |
| `pipl` | low | medium | PIPL (China Personal Information Protection Law) reference detected |
| `popia` | low | medium | POPIA (South Africa) reference detected |
| `soc2-reference` | low | medium | SOC 2 reference detected |
| `soc2-trust-criteria` | medium | high | SOC 2 trust service criteria detected |
| `sox-compliance` | low | medium | SOX compliance reference detected |

## container

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `dockerfile-cap-add-all` | high | high | Detects Docker run or Dockerfile with --cap-add=ALL or cap_add: - ALL |
| `dockerfile-exposed-socket` | critical | high | Detects Docker socket mount which can give container full Docker access |
| `dockerfile-privileged-mode` | critical | high | Detects Docker container running in privileged mode with full host access |
| `dockerfile-running-as-root` | high | high | Detects Dockerfile or Docker run with user set to root or UID 0 |

## data-visualization

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `chart-accessibility` | medium | high | Chart accessibility issue detected - missing ARIA attributes or disabled accessibility features |
| `chart-config` | medium | high | Chart configuration issue detected - potential performance or display problem |
| `chart-types` | medium | high | Chart type mismatch detected - inappropriate chart type for data volume |
| `color-schemes` | medium | high | Color scheme issue detected - invalid hex color format or poor contrast |
| `mobile-optimization` | medium | high | Mobile optimization issue detected - charts may not render properly on mobile devices |

## devops

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `ansible-vault` | medium | high | Ansible vault encrypted content detected |
| `ci-bypass` | high | high | CI/CD bypass marker detected |
| `ci-secret-hardcoded` | critical | high | Hardcoded CI/CD secret detected |
| `debug-endpoint` | low | medium | Debug/test endpoint detected |
| `docker-socket` | high | high | Docker socket reference detected |
| `dockerignore-missing` | low | medium | Dockerignore file reference detected |
| `env-file-in-git` | high | high | .env file may be committed to git |
| `exposed-port` | low | high | Exposed port in Dockerfile detected |
| `hardcoded-ip` | medium | medium | Hardcoded IP address detected |
| `kubeconfig-reference` | medium | high | Kubernetes config reference detected |
| `latest-tag` | medium | high | Using latest tag in Dockerfile |
| `privileged-container` | high | high | Privileged container configuration detected |
| `root-user` | medium | high | Root user in Dockerfile detected |
| `secrets-in-dockerfile` | high | medium | Potential secret in Dockerfile detected |
| `terraform-state` | high | high | Terraform state file detected |

## finance

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `aba-routing-number` | medium | high | ABA routing number detected |
| `ethereum-address` | medium | high | Ethereum address detected |
| `finance-bitcoin-address` | medium | high | Bitcoin address detected |
| `finance-iban` | medium | high | IBAN (International Bank Account Number) detected |
| `stripe-publishable-key` | medium | high | Stripe publishable key detected |
| `swift-bic` | medium | high | SWIFT/BIC code detected |

## frameworks

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `angular-bypass-security-trust` | high | high | Angular security bypass detected. bypassSecurityTrust calls disable Angular's built-in XSS protection. |
| `angular-innerhtml-xss` | high | high | Angular innerHTML assignment detected. This can introduce XSS vulnerabilities. |
| `django-csrf-exempt` | high | high | Missing CSRF protection. Forms should include CSRF tokens. |
| `django-debug-print` | low | high | Debug code should be removed before production deployment. |
| `django-secret-key-hardcoded` | high | high | Hardcoded Django SECRET_KEY detected. Use environment variables instead. |
| `express-eval-usage` | high | high | Express.js eval() with user input detected. This can lead to remote code execution. |
| `express-sql-injection` | high | high | Express.js SQL query with template literal interpolation detected. This can lead to SQL injection. |
| `flask-debug-enabled` | medium | high | Flask debug mode enabled. This should be disabled in production. |
| `flask-sqlalchemy-raw-sql` | high | high | Flask-SQLAlchemy raw SQL with string interpolation detected. This can lead to SQL injection. |
| `go-defer-goroutine-leak` | high | high | defer with goroutine may cause goroutine leak. |
| `go-json-marshal-error-ignore` | medium | high | json.Marshal/Unmarshal result checked without error handling. |
| `go-strconv-error-ignore` | medium | high | strconv function result used without error check. |
| `laravel-app-key-hardcoded` | high | high | Laravel APP_KEY hardcoded in source. This should be stored in environment variables. |
| `laravel-raw-db-query` | high | high | Laravel raw database query with string formatting detected. This can lead to SQL injection. |
| `nodejs-hardcoded-jwt-secret` | high | high | Hardcoded JWT secret detected. Use environment variables instead. |
| `nodejs-sync-fs-readfile` | high | high | Synchronous file read detected. Use async version for better performance. |
| `nodejs-todo-development` | low | high | TODO/FIXME comment detected. Pending tasks should be tracked in issue tracker. |
| `rails-raw-sql-injection` | high | high | Rails raw SQL execution detected. This can lead to SQL injection. |
| `rails-secret-key-hardcoded` | high | high | Rails secret key hardcoded in source. Use environment variables. |
| `react-console-log-dev` | low | high | Debug logging detected. Remove before production deployment. |
| `react-missing-key-prop` | low | high | React map without key prop detected. |
| `rust-env-macro` | medium | high | Rust env! macro detected. This will panic if environment variable is not set. |
| `rust-expect-usage` | medium | high | Rust .expect() call detected. This can panic. |
| `rust-hardcoded-secret` | critical | high | Hardcoded secret detected in Rust code. |
| `rust-println-debug` | low | high | Rust debug println! with formatting detected. |
| `rust-unsafe-block` | high | high | Rust unsafe block detected. Bypasses memory safety guarantees. |
| `rust-unsafe-extern` | high | high | Rust unsafe extern block detected. |
| `rust-unwrap-usage` | medium | high | Rust .unwrap() call detected. This can panic. |
| `spring-deserialization-read-object` | high | high | Java deserialization detected. Unsafe deserialization can lead to RCE. |
| `vue-template-injection` | high | high | Vue.js template injection detected. |
| `vue-v-html-xss` | high | high | Vue.js v-html directive detected. This can introduce XSS vulnerabilities. |

## git-hygiene

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `branch-naming-bugfix` | low | high | Bugfix branch naming convention detected |
| `branch-naming-feature` | low | high | Feature branch naming convention detected |
| `branch-naming-hotfix` | low | high | Hotfix branch naming convention detected |
| `branch-naming-release` | low | high | Release branch naming convention detected |
| `commit-ampersand` | low | low | Commit message contains '&' instead of 'and' |
| `commit-message-conventional` | low | medium | Conventional commit message format detected |
| `commit-sha-reference` | low | high | Full commit SHA reference detected |
| `commitizen-config` | low | high | Commitizen configuration detected |
| `force-push-detected` | medium | high | Force push command detected |
| `git-commit-signoff` | low | high | Git sign-off detected (DCO) |
| `git-commit-verify` | low | high | GPG commit signing enabled |
| `git-flow-model` | low | high | Git Flow branching model reference |
| `git-hooks-husky` | low | high | Husky git hooks directory detected |
| `git-hygiene-dependabot-config` | low | high | Dependabot configuration detected |
| `git-hygiene-github-actions-workflow` | low | high | GitHub Actions workflow detected |
| `git-hygiene-renovate-config` | low | high | Renovate configuration detected |
| `git-lfs` | low | high | Git LFS usage detected |
| `git-stash` | low | high | Git stash command detected |
| `git-worktree` | low | high | Git worktree command detected |
| `gitattributes-entry` | low | high | .gitattributes file detected |
| `github-issue-reference` | low | high | GitHub issue reference in commit |
| `gitignore-entry` | low | high | .gitignore file detected |
| `gitmodules-entry` | medium | high | .gitmodules file detected (git submodule) |
| `merge-commit` | low | high | Merge commit message detected |
| `merge-conflict` | high | high | Unresolved merge conflict marker detected |
| `pre-commit-config` | low | high | Pre-commit configuration detected |
| `semantic-release-config` | low | high | Semantic release configuration detected |
| `tag-reference` | low | high | Semantic version tag reference detected |

## git-ops

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `git-credential-leak` | critical | high | Detects potential git credential leakage in configuration or URLs |
| `git-ops-force-push-detected` | high | high | Detects force push commands which can overwrite remote history |
| `protected-branch-delete` | critical | high | Detects commands that delete or modify protected branches |

## graphql

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `graphql-debug-mode` | high | high | Detects GraphQL with debug mode enabled |
| `graphql-field-cost-undefined` | medium | high | Detects GraphQL without field cost analysis enabled |
| `graphql-introspection-enabled` | medium | high | Detects GraphQL with introspection enabled in production |
| `graphql-query-depth-unlimited` | high | high | Detects GraphQL with unlimited query depth |

## healthcare

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `clinical-trial-id` | medium | high | Clinical trial identifier detected |
| `healthcare-code` | medium | high | Healthcare code detected (CPT, HCPCS, ICD-10) |
| `healthcare-medical-record-number` | medium | high | Medical record number detected |
| `healthcare-prescription-number` | medium | high | Prescription number detected |
| `insurance-number` | medium | high | Insurance number detected |
| `medical-license-number` | medium | high | Medical license number detected |
| `patient-id` | medium | high | Patient identifier detected |

## infrastructure

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `cloudformation-conditions` | low | high | CloudFormation Conditions section detected |
| `cloudformation-mappings` | low | high | CloudFormation Mappings section detected |
| `cloudformation-outputs` | low | high | CloudFormation Outputs section detected |
| `cloudformation-parameters` | low | high | CloudFormation Parameters section detected |
| `cloudformation-resources` | low | high | CloudFormation Resources section detected |
| `cloudformation-template-format-version` | low | high | CloudFormation template version detected |
| `dockerfile-add` | medium | high | Dockerfile ADD instruction detected |
| `dockerfile-cmd` | low | high | Dockerfile CMD instruction detected |
| `dockerfile-copy` | low | high | Dockerfile COPY instruction detected |
| `dockerfile-env` | medium | high | Dockerfile ENV instruction detected |
| `dockerfile-expose` | low | high | Dockerfile EXPOSE instruction detected |
| `dockerfile-from` | low | high | Dockerfile FROM instruction detected |
| `dockerfile-healthcheck` | low | high | Dockerfile HEALTHCHECK instruction detected |
| `dockerfile-run` | low | high | Dockerfile RUN instruction detected |
| `dockerfile-user` | low | high | Dockerfile USER instruction detected |
| `dockerfile-volume` | low | high | Dockerfile VOLUME instruction detected |
| `dockerfile-workdir` | low | high | Dockerfile WORKDIR instruction detected |
| `helm-chart` | low | high | Helm Chart detected (apiVersion v2) |
| `helm-templates` | low | high | Helm template file detected |
| `helm-values` | low | high | Helm values file detected |
| `kubernetes-clusterrole` | medium | high | Kubernetes ClusterRole detected |
| `kubernetes-configmap` | low | high | Kubernetes ConfigMap detected |
| `kubernetes-cronjob` | low | high | Kubernetes CronJob detected |
| `kubernetes-daemonset` | low | high | Kubernetes DaemonSet detected |
| `kubernetes-deployment` | low | high | Kubernetes Deployment detected |
| `kubernetes-hpa` | low | high | Kubernetes HPA detected |
| `kubernetes-ingress` | low | high | Kubernetes Ingress detected |
| `kubernetes-job` | low | high | Kubernetes Job detected |
| `kubernetes-limitrange` | low | high | Kubernetes LimitRange detected |
| `kubernetes-namespace` | low | high | Kubernetes Namespace detected |
| `kubernetes-networkpolicy` | medium | high | Kubernetes NetworkPolicy detected |
| `kubernetes-pdb` | low | high | Kubernetes PodDisruptionBudget detected |
| `kubernetes-persistentvolume` | low | high | Kubernetes PersistentVolume detected |
| `kubernetes-pod` | low | high | Kubernetes Pod detected |
| `kubernetes-priorityclass` | low | high | Kubernetes PriorityClass detected |
| `kubernetes-resource-quota` | low | high | Kubernetes ResourceQuota detected |
| `kubernetes-role` | medium | high | Kubernetes Role detected |
| `kubernetes-secret` | high | high | Kubernetes Secret detected |
| `kubernetes-service` | low | high | Kubernetes Service detected |
| `kubernetes-serviceaccount` | low | high | Kubernetes ServiceAccount detected |
| `kubernetes-statefulset` | low | high | Kubernetes StatefulSet detected |
| `terraform-backend` | medium | high | Terraform backend configuration detected |
| `terraform-count` | medium | high | Terraform count detected |
| `terraform-data-source` | low | high | Terraform data source detected |
| `terraform-dynamic-block` | medium | high | Terraform dynamic block detected |
| `terraform-for-each` | medium | high | Terraform for_each detected |
| `terraform-locals` | low | high | Terraform locals block detected |
| `terraform-module` | low | high | Terraform module usage detected |
| `terraform-output` | low | high | Terraform output definition detected |
| `terraform-provider-aws` | low | high | AWS provider declaration detected |
| `terraform-provider-azure` | low | high | Azure provider declaration detected |
| `terraform-provider-gcp` | low | high | GCP provider declaration detected |
| `terraform-resource` | low | high | Terraform resource definition detected |
| `terraform-sensitive-variable` | high | high | Terraform sensitive variable detected |
| `terraform-variable` | low | high | Terraform variable definition detected |

## kubernetes

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `hostnetwork` | high | high | Pod uses host network |
| `hostpid` | high | high | Pod uses host PID namespace |
| `k8s-allow-privilege-escalation` | high | high | Container allows privilege escalation |
| `k8s-empty-dir-memory-backed` | medium | high | EmptyDir volume uses memory-backed storage |
| `k8s-missing-capability-drop` | medium | medium | Security context defined but missing capability drop |
| `k8s-no-network-policy` | medium | high | No network policy defined for namespace |
| `k8s-run-as-non-root` | high | high | Container run as root or missing runAsNonRoot configuration |
| `kubernetes-latest-tag` | medium | high | Container image uses latest tag |
| `kubernetes-privileged-container` | critical | high | Container runs in privileged mode |
| `no-resource-limits` | medium | high | Container has no resource limits defined |
| `secrets-in-manifest` | high | high | Secrets may be exposed in Kubernetes manifests |

## llm-guardrails

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `bias-detection` | medium | medium | Potential bias detected |
| `code-injection-request` | high | high | Request for malicious code guidance |
| `copyright-material` | medium | medium | Copyright material reference detected |
| `data-exfiltration-attempt` | critical | high | Data exfiltration attempt detected |
| `financial-advice-request` | medium | medium | Financial advice request detected |
| `harmful-content-marker` | high | medium | Potential harmful content marker detected |
| `hate-speech-marker` | critical | high | Potential hate speech marker detected |
| `hypothetical-malware` | medium | medium | Hypothetical malware request detected |
| `jailbreak-attempt` | high | high | Jailbreak attempt detected |
| `legal-advice-request` | medium | high | Legal advice request detected |
| `llm-guardrails-prompt-injection` | high | high | Potential prompt injection attempt |
| `medical-advice-request` | medium | high | Medical advice request detected |
| `output-filtering-enabled` | low | high | Output filtering mechanism detected |
| `pii-leak-risk` | high | medium | Potential PII leak instruction detected |
| `pii-output-marker` | high | high | PII marker detected in content |
| `privacy-breach-request` | high | high | Privacy breach request detected |
| `profanity-detected` | low | high | Profanity detected |
| `role-play-override` | medium | medium | Role-play override attempt detected |
| `self-harm-content` | critical | high | Self-harm content detected |
| `sql-injection-request` | high | high | Request for SQL injection guidance |
| `system-prompt-override` | medium | high | System prompt override attempt detected |
| `token-limit-warning` | low | high | Token limit configuration detected |
| `toxicity-marker` | high | high | Toxicity marker detected |
| `trademark-reference` | low | medium | Trademark reference detected |
| `violence-glorification` | critical | high | Violence glorification detected |

## metadata

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `backup-file` | low | high | Detects backup files that may contain sensitive data |
| `ide-config-leak` | medium | high | Detects IDE configuration files that may contain sensitive settings |
| `os-cache-file` | low | high | Detects operating system cache files that may contain metadata |
| `temporary-file` | low | high | Detects temporary files that may contain sensitive data |

## performance

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `box-inside-loop` | low | medium | Box allocation inside loop - consider alternatives |
| `console-log-production` | low | high | Console logging in production code |
| `document-write` | high | high | document.write() detected - blocks page parsing |
| `event-listener-leak` | medium | medium | Event listener added without removeEventListener |
| `expensive-computation-loop` | medium | medium | Expensive computation inside loop |
| `force-reflow` | medium | high | Reading layout properties causes forced reflow |
| `global-variable` | low | medium | Global variable assignment detected |
| `gzip-not-enabled` | medium | high | gzip compression not enabled |
| `inner-html-assignment` | medium | medium | innerHTML assignment may cause performance issues |
| `missing-database-index` | medium | low | CREATE TABLE without explicit index |
| `missing-limit` | medium | high | Query missing LIMIT clause |
| `multiple-redirects` | low | medium | HTTP redirect detected |
| `n-plus-one-query` | medium | low | Potential N+1 query pattern |
| `no-cache-headers` | low | high | Cache headers not detected in response |
| `no-connection-pool` | medium | medium | Database connection without pooling |
| `regex-in-loop` | medium | high | Regex creation inside loop - compile outside |
| `select-star` | low | high | SELECT * detected - consider selecting specific columns |
| `string-concatenation-loop` | medium | high | String concatenation in loop - use StringBuilder or join() |
| `sync-in-async` | medium | medium | Blocking *Sync() call detected; prefer the async API |
| `synchronous-xmlhttprequest` | high | high | Synchronous XMLHttpRequest blocks UI thread |
| `unsized-image` | low | high | Image without explicit dimensions |
| `vector-initial-capacity` | low | medium | Vec::new() without capacity hint - consider Vec::with_capacity() |

## pii

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `api-key-field` | high | high | API key field with value detected |
| `australian-tfn` | high | medium | Australian Tax File Number (TFN) detected |
| `aws-access-key` | critical | high | AWS Access Key ID detected |
| `bank-routing-number` | high | medium | Bank routing number (ABA) detected |
| `bitcoin-address` | medium | high | Bitcoin address detected |
| `canadian-sin` | high | high | Canadian Social Insurance Number (SIN) detected |
| `consent-record` | low | high | User consent record detected |
| `credit-card-amex` | critical | high | American Express credit card number detected |
| `credit-card-discover` | critical | high | Discover credit card number detected |
| `credit-card-mastercard` | critical | high | Mastercard credit card number detected |
| `credit-card-number-generic` | critical | high | Generic credit card number detected |
| `credit-card-visa` | critical | high | Visa credit card number detected |
| `cvv` | critical | high | Card verification value (CVV/CVC) detected |
| `data-processing` | low | high | Data processing agreement reference detected |
| `date-of-birth` | medium | medium | Date of birth field detected |
| `drivers-license` | high | medium | Driver's license number detected |
| `ein` | medium | high | Employer Identification Number (EIN) detected |
| `email-address` | low | high | Email address detected |
| `full-name` | low | medium | Full name field detected |
| `gdpr-personal-data` | low | high | Reference to personal data detected |
| `health-insurance-number` | high | medium | Health insurance number detected |
| `iban` | high | high | International Bank Account Number (IBAN) detected |
| `indian-aadhaar` | high | high | Indian Aadhaar number detected |
| `international-phone` | low | medium | International phone number detected |
| `itin` | high | high | Individual Taxpayer Identification Number (ITIN) detected |
| `medical-record-number` | high | medium | Medical Record Number (MRN) detected |
| `military-id` | high | medium | Military ID detected |
| `national-id` | high | medium | National ID number detected |
| `passport-number` | high | medium | Passport number detected |
| `password-field` | high | high | Password field with value detected |
| `phone-number` | low | medium | Phone number detected |
| `prescription-number` | medium | medium | Prescription number detected |
| `right-to-erasure` | low | high | Right to erasure request detected |
| `ssn` | high | high | Social Security Number (SSN) detected |
| `ssn-no-dashes` | high | medium | Possible SSN without dashes detected |
| `street-address` | medium | medium | Street address detected |
| `uk-national-insurance` | high | high | UK National Insurance number detected |
| `username-field` | low | medium | Username field with value detected |
| `zip-code` | low | high | US ZIP code detected |

## pwa

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `caching-strategy` | medium | high | PWA caching strategy issue |
| `manifest` | medium | high | PWA manifest configuration issue |
| `offline-support` | medium | high | PWA offline support issue |
| `service-worker` | medium | high | PWA service worker issue |
| `shortcuts` | medium | high | PWA shortcuts configuration issue |

## secrets

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `anthropic-api-key` | critical | high | Anthropic API Key detected |
| `api-key-in-url` | high | high | API Key embedded in URL detected |
| `azure-api-key` | high | low | Potential Azure API Key detected |
| `basic-auth-credentials` | high | high | Basic Authentication credentials detected |
| `bearer-token` | high | high | Bearer Token detected |
| `connection-string-with-password` | critical | medium | Connection string with password detected |
| `database-connection-string` | critical | high | Database connection string detected |
| `discord-api-key` | critical | high | Discord API Key detected |
| `dropbox-api-key` | high | medium | Dropbox API Key detected |
| `ec-private-key` | critical | high | EC Private Key detected |
| `env-credential-assignment` | high | medium | Credential-like variable assigned a literal value |
| `facebook-access-token` | critical | high | Facebook Access Token detected |
| `firebase-api-key` | high | high | Firebase API Key detected |
| `generic-api-key` | high | medium | Generic API Key detected |
| `generic-secret` | high | medium | Generic secret/token detected |
| `github-oauth-token` | critical | high | GitHub OAuth Token detected |
| `github-ssh-key` | critical | high | OpenSSH Private Key detected (possibly GitHub) |
| `gitlab-token` | critical | high | GitLab Personal Access Token detected |
| `google-api-key` | critical | high | Google API Key detected |
| `google-oauth-token` | critical | high | Google OAuth Token detected |
| `hardcoded-password` | high | medium | Hardcoded password detected |
| `hardcoded-username` | medium | low | Hardcoded username detected |
| `heroku-api-key` | critical | high | Heroku API Key detected |
| `huggingface-api-key` | critical | high | HuggingFace API Key detected |
| `jwt-token` | high | medium | JWT Token detected |
| `mailchimp-api-key` | critical | high | Mailchimp API Key detected |
| `npm-token` | critical | high | NPM Access Token detected |
| `openai-api-key` | critical | high | OpenAI API Key detected |
| `pgp-private-key` | critical | high | PGP Private Key detected |
| `private-key-encrypted` | high | high | Encrypted Private Key detected |
| `rsa-private-key` | critical | high | RSA Private Key detected |
| `secrets-aws-access-key` | critical | high | AWS Access Key ID detected |
| `secrets-aws-secret-key` | critical | high | AWS Secret Access Key detected |
| `secrets-github-token` | critical | high | GitHub Token detected |
| `secrets-sendgrid-api-key` | critical | high | SendGrid API Key detected |
| `secrets-slack-token` | critical | high | Slack Token detected |
| `secrets-stripe-api-key` | critical | high | Stripe API Key detected |
| `secrets-stripe-publishable-key` | medium | high | Stripe Publishable Key detected |
| `secrets-twilio-api-key` | critical | high | Twilio API Key detected |
| `ssh-private-key` | critical | high | SSH Private Key detected |
| `twitter-api-key` | high | medium | Twitter API Key detected |

## security-hardening

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `aws-secret-key` | critical | high | AWS secret access key detected |
| `basic-auth-url` | high | high | Basic authentication credentials in URL |
| `bearer-token-url` | medium | high | Bearer token detected in code |
| `csrf-missing` | low | low | CSRF protection reference detected |
| `deserialization-vulnerability` | critical | high | Potential insecure deserialization vulnerability |
| `eval-usage` | high | high | Dangerous eval() usage detected |
| `github-token` | critical | high | GitHub token detected |
| `hardcoded-encryption-key` | critical | high | Hardcoded encryption key detected |
| `hardcoded-iv` | high | high | Hardcoded IV detected for encryption |
| `insecure-cookie` | medium | high | Insecure cookie configuration detected |
| `insecure-random` | medium | high | Insecure random number generation (Math.random) |
| `jwt-secret-hardcoded` | high | high | Hardcoded JWT secret detected |
| `ldap-injection` | high | medium | Potential LDAP injection vulnerability |
| `mailgun-api-key` | critical | medium | Mailgun API key detected |
| `password-in-url` | high | high | Password embedded in URL detected |
| `private-key-exposed` | critical | high | Private key exposed in code |
| `security-hardening-aws-access-key` | critical | high | AWS access key ID detected |
| `security-hardening-command-injection` | critical | medium | Potential command injection vulnerability |
| `security-hardening-jwt-none-algorithm` | critical | high | JWT 'none' algorithm vulnerability detected |
| `security-hardening-path-traversal` | high | medium | Potential path traversal vulnerability |
| `security-hardening-xml-external-entity` | critical | high | XML External Entity (XXE) vulnerability detected |
| `sendgrid-api-key` | critical | high | SendGrid API key detected |
| `sensitive-file-access` | medium | medium | Access to sensitive system files detected |
| `setuid-root` | high | medium | Setuid/Setgid permissions detected |
| `slack-token` | critical | high | Slack token detected |
| `sql-query` | low | low | SQL query detected (potential SQL injection) |
| `ssti-template` | high | medium | Potential server-side template injection |
| `stripe-api-key` | critical | high | Stripe API key detected |
| `twilio-api-key` | critical | high | Twilio API key detected |
| `weak-ssl` | high | high | Weak cryptographic protocol/algorithm detected |
| `world-writable` | high | high | World-writable file permissions detected |
| `xpath-injection` | high | medium | Potential XPath injection vulnerability |
| `xss-vulnerability` | high | medium | Potential XSS vulnerability (unsafe DOM manipulation) |

## shift-left

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `azure-pipeline` | low | high | Azure Pipeline detected |
| `checkov-config` | low | high | IaC security scanning tool detected |
| `circleci-config` | low | high | CircleCI config detected |
| `codecov-config` | low | high | Code coverage config detected |
| `drone-ci` | low | high | Drone CI config detected |
| `gitlab-ci-pipeline` | low | high | GitLab CI pipeline detected |
| `grype-config` | low | high | Container vulnerability scanning with Grype detected |
| `integration-test-marker` | low | high | Integration test marker detected |
| `jenkinsfile` | low | high | Jenkinsfile detected |
| `pr-review-marker` | low | medium | PR review marker detected |
| `precommit-marker` | low | high | Pre-commit hook marker detected |
| `security-test-marker` | low | high | Security test marker detected |
| `shift-left-dependabot-config` | low | high | Dependabot config detected |
| `shift-left-github-actions-workflow` | low | high | GitHub Actions workflow detected |
| `snyk-config` | medium | high | Snyk security config detected |
| `sonarqube-config` | low | high | SonarQube config detected |
| `terraform-validate` | low | high | Terraform validate command detected |
| `travis-yml` | low | high | Travis CI config detected |
| `trivy-config` | low | high | Container vulnerability scanning tool detected |
| `unit-test-marker` | low | high | Unit test marker detected |

## supply-chain

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `cargo-audit` | medium | high | Cargo audit command detected |
| `cargo-lock` | medium | high | Rust Cargo.lock detected |
| `cargo-toml` | low | high | Rust Cargo.toml detected |
| `dependabot-config` | low | high | Dependabot configuration detected |
| `dockerfile-base-image` | medium | high | Docker base image reference detected |
| `dotnet-csproj` | low | high | .NET project file detected |
| `github-actions-workflow` | low | high | GitHub Actions workflow detected |
| `github-advisory` | high | high | GitHub security advisory reference detected |
| `go-mod` | low | high | Go module file detected |
| `go-replace-directive` | medium | high | Go replace directive detected |
| `go-sum` | medium | high | Go checksum file detected |
| `gradle-build` | low | high | Gradle build file detected |
| `gradle-lockfile` | medium | high | Gradle lockfile detected |
| `gradle-wrapper` | low | high | Gradle wrapper detected |
| `helm-chart-dependency` | medium | high | Helm chart dependency detected |
| `maven-wrapper` | low | high | Maven wrapper detected |
| `npm-audit` | medium | high | NPM audit command detected |
| `npm-shrinkwrap` | medium | high | NPM shrinkwrap file detected |
| `nuget-config` | low | high | NuGet config detected |
| `package-json` | low | high | package.json file detected |
| `packages-config` | low | high | .NET packages.config detected |
| `pipfile` | low | high | Pipfile detected |
| `pipfile-lock` | medium | high | Pipfile.lock detected |
| `pnpm-lockfile` | low | high | PNPM lockfile detected |
| `poetry-lock` | medium | high | Poetry lock file detected |
| `pom-xml` | low | high | Maven pom.xml detected |
| `pyproject-toml` | low | high | Python pyproject.toml detected |
| `renovate-config` | low | high | Renovate configuration detected |
| `requirements-txt` | low | high | Python requirements file detected |
| `safety-db` | medium | high | Python safety check detected |
| `sbom-cyclonedx` | medium | high | CycloneDX SBOM detected |
| `sbom-spdx` | medium | high | SPDX SBOM detected |
| `setup-py` | low | high | Python setup.py detected |
| `unknown-npm-package` | low | low | NPM package installation detected |
| `yarn-lockfile` | low | high | Yarn lockfile detected |

## terraform

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `db-public-access` | high | high | Database instance configured with public accessibility |
| `hardcoded-tf-secrets` | critical | high | Hardcoded secrets detected in Terraform configuration |
| `s3-public-access` | high | high | S3 bucket configured with public access |
| `tf-ecs-no-secrets` | medium | high | ECS task definition detected - ensure secrets are not hardcoded |
| `tf-ecs-privileged` | critical | high | ECS task definition with privileged mode enabled |
| `tf-s3-unencrypted` | high | high | S3 bucket without server-side encryption |
| `unencrypted-storage` | high | high | Storage resource configured without encryption |

## typescript

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `arguments-object-usage` | low | medium | `arguments` object used; prefer rest parameters |
| `async-promise-executor` | medium | high | Async Promise executor swallows rejections |
| `double-type-assertion` | medium | high | Double type assertion casts through unknown/any |
| `empty-interface` | low | high | Empty interface declared |
| `namespace-declaration` | low | medium | TypeScript namespace detected; prefer ES modules |
| `object-function-type` | low | medium | Useless broad type annotation (object/Object/Function) |
| `prototype-builtin-call` | low | high | Object prototype method called directly; use Object.hasOwn |
| `require-in-typescript` | low | high | CommonJS require() used in TypeScript; prefer ES imports |
| `return-await` | low | medium | Redundant `return await` outside try/catch |
| `ts-ignore-comment` | medium | high | @ts-ignore suppresses type errors indefinitely; use @ts-expect-error |
| `ts-nocheck` | high | high | @ts-nocheck disables type checking for the whole file |
| `typescript-any-alias` | medium | high | Type alias resolves to `any` |
| `typescript-explicit-any` | medium | high | Explicit `any` defeats TypeScript type checking |

## web-development

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `bundler-optimization` | low | high | Bundler optimization issue |
| `error-boundaries` | low | high | React error boundary implementation |
| `form-validation` | low | high | Form validation issue |
| `incorrect-semantic-html` | medium | high | Incorrect semantic HTML usage |
| `inefficient-css` | low | high | Inefficient CSS implementation |
| `missing-prop-validation` | medium | high | Missing prop type validation |
| `nextjs` | low | high | Next.js specific pattern |
| `poor-error-boundary` | high | high | Poor error boundary implementation |
| `react-optimization` | low | high | React optimization issue |
| `seo-meta-tags` | low | high | SEO meta tag configuration |
| `state-management` | low | high | State management issue |

## web-security

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| `api-key-exposure` | high | high | API key in source code |
| `command-injection` | critical | high | Potential OS command injection |
| `content-security-policy` | low | high | Content-Security-Policy header detected |
| `cors-misconfiguration` | medium | high | CORS misconfiguration detected (wildcard origin) |
| `csrf-missing-token` | medium | medium | State-changing operation may lack CSRF protection |
| `csrf-token-header` | low | high | CSRF token header detected |
| `debug-mode` | medium | high | Debug mode enabled in production |
| `directory-traversal` | high | medium | URL-encoded directory traversal sequence detected |
| `dom-xss` | high | high | Potential DOM XSS vulnerability |
| `executable-file-upload` | critical | high | Executable file upload detected |
| `graphql-batch-limit` | medium | high | GraphQL depth limiting detected |
| `graphql-introspection` | medium | high | GraphQL introspection enabled |
| `hardcoded-credential` | critical | high | Hardcoded credential detected |
| `hsts-missing` | medium | high | HSTS header not detected |
| `insecure-deserialization` | critical | high | Potential insecure deserialization |
| `jwt-none-algorithm` | critical | high | JWT with 'none' algorithm detected |
| `missing-authentication` | high | medium | API endpoint may lack authentication |
| `missing-security-headers` | medium | high | Security headers detected |
| `open-redirect` | medium | medium | Potential open redirect vulnerability |
| `path-traversal` | high | medium | Potential path traversal vulnerability |
| `rate-limit-missing` | medium | medium | Authentication route without visible rate limiting; brute-force protection not evident |
| `redirect-to-relative` | low | high | Redirect to relative path |
| `reflected-xss` | high | medium | Potential reflected XSS vulnerability |
| `server-version` | low | high | Server version header detected |
| `session-fixation` | medium | high | Potential session fixation vulnerability |
| `sql-injection` | high | medium | Potential SQL injection vulnerability |
| `ssrf` | high | medium | Potential Server-Side Request Forgery (SSRF) |
| `ssrf-localhost` | medium | medium | Potential SSRF targeting internal resources |
| `stack-trace-exposure` | low | high | Stack trace exposure detected |
| `stored-xss` | high | medium | Potential stored XSS via innerHTML |
| `unrestricted-file-upload` | high | medium | File upload without validation |
| `weak-password-hash` | high | high | Weak password hashing algorithm detected |
| `x-content-type-options` | medium | high | X-Content-Type-Options header detected |
| `x-frame-options` | medium | high | X-Frame-Options header detected |
| `xml-external-entity` | critical | high | XML External Entity (XXE) detected |
| `xss-via-url` | medium | medium | Potential XSS via URL parameters |
| `xxe` | critical | high | XXE protection disabled |
