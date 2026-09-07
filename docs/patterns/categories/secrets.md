# secrets patterns

Credentials, API keys, and tokens

**41 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`anthropic-api-key`](#anthropic-api-key) | critical | high | Anthropic API Key detected |
| [`api-key-in-url`](#api-key-in-url) | high | high | API Key embedded in URL detected |
| [`azure-api-key`](#azure-api-key) | high | low | Potential Azure API Key detected |
| [`basic-auth-credentials`](#basic-auth-credentials) | high | high | Basic Authentication credentials detected |
| [`bearer-token`](#bearer-token) | high | high | Bearer Token detected |
| [`connection-string-with-password`](#connection-string-with-password) | critical | medium | Connection string with password detected |
| [`database-connection-string`](#database-connection-string) | critical | high | Database connection string detected |
| [`discord-api-key`](#discord-api-key) | critical | high | Discord API Key detected |
| [`dropbox-api-key`](#dropbox-api-key) | high | medium | Dropbox API Key detected |
| [`ec-private-key`](#ec-private-key) | critical | high | EC Private Key detected |
| [`env-credential-assignment`](#env-credential-assignment) | high | medium | Credential-like variable assigned a literal value |
| [`facebook-access-token`](#facebook-access-token) | critical | high | Facebook Access Token detected |
| [`firebase-api-key`](#firebase-api-key) | high | high | Firebase API Key detected |
| [`generic-api-key`](#generic-api-key) | high | medium | Generic API Key detected |
| [`generic-secret`](#generic-secret) | high | medium | Generic secret/token detected |
| [`github-oauth-token`](#github-oauth-token) | critical | high | GitHub OAuth Token detected |
| [`github-ssh-key`](#github-ssh-key) | critical | high | OpenSSH Private Key detected (possibly GitHub) |
| [`gitlab-token`](#gitlab-token) | critical | high | GitLab Personal Access Token detected |
| [`google-api-key`](#google-api-key) | critical | high | Google API Key detected |
| [`google-oauth-token`](#google-oauth-token) | critical | high | Google OAuth Token detected |
| [`hardcoded-password`](#hardcoded-password) | high | medium | Hardcoded password detected |
| [`hardcoded-username`](#hardcoded-username) | medium | low | Hardcoded username detected |
| [`heroku-api-key`](#heroku-api-key) | critical | high | Heroku API Key detected |
| [`huggingface-api-key`](#huggingface-api-key) | critical | high | HuggingFace API Key detected |
| [`jwt-token`](#jwt-token) | high | medium | JWT Token detected |
| [`mailchimp-api-key`](#mailchimp-api-key) | critical | high | Mailchimp API Key detected |
| [`npm-token`](#npm-token) | critical | high | NPM Access Token detected |
| [`openai-api-key`](#openai-api-key) | critical | high | OpenAI API Key detected |
| [`pgp-private-key`](#pgp-private-key) | critical | high | PGP Private Key detected |
| [`private-key-encrypted`](#private-key-encrypted) | high | high | Encrypted Private Key detected |
| [`rsa-private-key`](#rsa-private-key) | critical | high | RSA Private Key detected |
| [`secrets-aws-access-key`](#secrets-aws-access-key) | critical | high | AWS Access Key ID detected |
| [`secrets-aws-secret-key`](#secrets-aws-secret-key) | critical | high | AWS Secret Access Key detected |
| [`secrets-github-token`](#secrets-github-token) | critical | high | GitHub Token detected |
| [`secrets-sendgrid-api-key`](#secrets-sendgrid-api-key) | critical | high | SendGrid API Key detected |
| [`secrets-slack-token`](#secrets-slack-token) | critical | high | Slack Token detected |
| [`secrets-stripe-api-key`](#secrets-stripe-api-key) | critical | high | Stripe API Key detected |
| [`secrets-stripe-publishable-key`](#secrets-stripe-publishable-key) | medium | high | Stripe Publishable Key detected |
| [`secrets-twilio-api-key`](#secrets-twilio-api-key) | critical | high | Twilio API Key detected |
| [`ssh-private-key`](#ssh-private-key) | critical | high | SSH Private Key detected |
| [`twitter-api-key`](#twitter-api-key) | high | medium | Twitter API Key detected |

## Pattern details

### anthropic-api-key

Anthropic API Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `anthropic`, `ai`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
sk-ant-[A-Za-z0-9_-]{48,}
```

**Reference**: <https://docs.anthropic.com/en/api>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
sk-ant-L…fY
```

### api-key-in-url

API Key embedded in URL detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3.5` |
| Tags | `api-key`, `url`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)[?&](api_key|api-key|apikey|access_token|auth_token)=[a-zA-Z0-9_-]{10,}
```

**Reference**: <https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure>

**Input that fires** (verified by the liveness test):

```text
&api_key=Xi-kkkaHRfT
```

### azure-api-key

Potential Azure API Key detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `low` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `azure`, `cloud`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
[a-zA-Z0-9+/]{32,}$
```

**Reference**: <https://docs.microsoft.com/en-us/azure/api-management/api-management-subscriptions>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
cz9SdGrT…qk/bQ5xZ+Ew
```

### basic-auth-credentials

Basic Authentication credentials detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `basic-auth`, `credential`, `auth` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)basic\s+[a-zA-Z0-9+/=]{10,}
```

**Reference**: <https://datatracker.ietf.org/doc/html/rfc7617>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
basic =kiJrCa4v…TV
```

### bearer-token

Bearer Token detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `bearer`, `token`, `auth` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)bearer\s+[a-zA-Z0-9_=-]{10,}
```

**Reference**: <https://datatracker.ietf.org/doc/html/rfc6750>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
bearer XD8rFTugPw=_H3ndKCe…Za
```

### connection-string-with-password

Connection string with password detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3` |
| Tags | `connection-string`, `password`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(server|host|data source).*(password|pwd).*[;=]
```

**Reference**: <https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
serverbp…WH;
```

### database-connection-string

Database connection string detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3.5` |
| Tags | `database`, `connection-string`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(mongodb|postgres|mysql|redis|mssql)://[^\s'"]{10,}
```

**Reference**: <https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure>

**Environment value that fires** (verified by the liveness test):

```text
mongodb://2DNmW.qeToXMvkba-s:3
```

### discord-api-key

Discord API Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `discord`, `api`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
[A-Za-z\d]{24}\.[\w-]{6}\.[\w-]{27}
```

**Reference**: <https://discord.com/developers/docs/reference>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
MKrFRF68…Aq.5yzCvp.tu_ec4L9…JV
```

### dropbox-api-key

Dropbox API Key detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `dropbox`, `api`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
[a-zA-Z0-9]{40,}
```

**Reference**: <https://www.dropbox.com/developers/reference>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
iCvVPxsL…bU
```

### ec-private-key

EC Private Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | allowed |
| Tags | `ec`, `private-key`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
-----BEGIN EC PRIVATE KEY-----
```

**Reference**: <https://man.openbsd.org/ssh-keygen.1>

**Input that fires** (verified by the liveness test):

```text
-----BEGIN EC PRIVATE KEY-----
```

### env-credential-assignment

Credential-like variable assigned a literal value

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3` |
| Tags | `secrets`, `env`, `assignment` |

**Match pattern** (Rust `regex` syntax):

```regex
\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*\s*[:=]\s*['"]?[A-Za-z0-9+/=_-]{8,}['"]?
```

**Exclude pattern** — a match span that also matches this
regex is suppressed:

```regex
(?i)\b(?:os\.environ|process\.env|std::env::var|getenv)\b|placeholder|example|changeme|your[-_]|<[^>]*>|\$\{
```
**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
WZGL65K9…9R : "CUi+SWCfZ+skb5Q9fN"
```

### facebook-access-token

Facebook Access Token detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `facebook`, `token`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
EAACEdEose0cBA[0-9A-Za-z]+
```

**Reference**: <https://developers.facebook.com/docs/facebook-login/guides/access-tokens>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
EAACEdEo…Cx
```

### firebase-api-key

Firebase API Key detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `firebase`, `google`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
AIza[0-9A-Za-z_-]{35}
```

**Reference**: <https://firebase.google.com/docs/api-keys>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
AIzaoPRA…-r
```

### generic-api-key

Generic API Key detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `api-key`, `generic`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(api[_-]?key|apikey|api_secret|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9]{16,}['"]
```

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
api-key = 'NXCX2NbA…SR'
```

### generic-secret

Generic secret/token detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `secret`, `token`, `generic` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(secret|token|auth)[_-]?(token|key|secret)?\s*[:=]\s*['"][A-Za-z0-9]{16,}['"]
```

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
secret_token = "G7hnVoqi…Ga"
```

### github-oauth-token

GitHub OAuth Token detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `github`, `oauth`, `token` |

**Match pattern** (Rust `regex` syntax):

```regex
gho_[A-Za-z0-9]{36}
```

**Reference**: <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-tokens>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
gho_5qdq…7R
```

### github-ssh-key

OpenSSH Private Key detected (possibly GitHub)

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | allowed |
| Tags | `ssh`, `private-key`, `github` |

**Match pattern** (Rust `regex` syntax):

```regex
-----BEGIN OPENSSH PRIVATE KEY-----
```

**Reference**: <https://man.openbsd.org/ssh-keygen.1>

**Input that fires** (verified by the liveness test):

```text
-----BEGIN OPENSSH PRIVATE KEY-----
```

### gitlab-token

GitLab Personal Access Token detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `gitlab`, `token`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
glpat-[A-Za-z0-9\-_]{20}
```

**Reference**: <https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
glpat-YH…qA
```

### google-api-key

Google API Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `google`, `cloud`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
AIza[0-9A-Za-z_-]{35}
```

**Reference**: <https://cloud.google.com/docs/authentication/api-keys>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
AIzaKXmC…7h
```

### google-oauth-token

Google OAuth Token detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `google`, `oauth`, `token` |

**Match pattern** (Rust `regex` syntax):

```regex
ya29\.[0-9A-Za-z_-]+
```

**Reference**: <https://developers.google.com/identity/protocols/oauth2>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
ya29.FEfwrhnm…C9
```

### hardcoded-password

Hardcoded password detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `2.5` |
| Tags | `password`, `hardcoded`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(password|passwd|pwd|secret)\s*[:=]\s*['"][^'"]{3,}['"]
```

**Reference**: <https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure>

**Input that fires** (verified by the liveness test):

```text
password = "kpC/'
```

### hardcoded-username

Hardcoded username detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `low` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `2` |
| Tags | `username`, `hardcoded`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)(username|user|login)\s*[:=]\s*['"][^'"]{2,}['"]
```

**Reference**: <https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
username = "t9/WmeEfpdv…zo"
```

### heroku-api-key

Heroku API Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `heroku`, `cloud`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
[h|H][e|E][r|R][o|O][k|K][u|U][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}
```

**Reference**: <https://devcenter.heroku.com/articles/authentication>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
H|r|KuF6AF46…48
```

### huggingface-api-key

HuggingFace API Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `huggingface`, `ai`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
hf_[A-Za-z0-9]{34,}
```

**Reference**: <https://huggingface.co/docs/api-keys>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
hf_cMmYw…UP
```

### jwt-token

JWT Token detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `jwt`, `token`, `auth` |

**Match pattern** (Rust `regex` syntax):

```regex
eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+
```

**Reference**: <https://datatracker.ietf.org/doc/html/rfc7519>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
eyJhbGci…J9.eyJzdWIi…n0.dozjgNry…8U
```

### mailchimp-api-key

Mailchimp API Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `mailchimp`, `email`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
[a-f0-9]{32}-us[0-9]{1,2}
```

**Reference**: <https://mailchimp.com/help/about-api-keys/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
8afb764d…98
```

### npm-token

NPM Access Token detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `npm`, `registry`, `token` |

**Match pattern** (Rust `regex` syntax):

```regex
npm_[A-Za-z0-9]{36}
```

**Reference**: <https://docs.npmjs.com/about-access-tokens>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
npm_aJEk…59
```

### openai-api-key

OpenAI API Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `openai`, `ai`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
sk-[A-Za-z0-9]{48}
```

**Reference**: <https://platform.openai.com/docs/api-keys>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
sk-U6JX9…bn
```

### pgp-private-key

PGP Private Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | allowed |
| Tags | `pgp`, `gpg`, `private-key` |

**Match pattern** (Rust `regex` syntax):

```regex
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

**Reference**: <https://gnupg.org/documentation/manuals/gnupg/GPG-Key-generation.html>

**Input that fires** (verified by the liveness test):

```text
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

### private-key-encrypted

Encrypted Private Key detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | allowed |
| Tags | `ssh`, `private-key`, `encrypted` |

**Match pattern** (Rust `regex` syntax):

```regex
-----BEGIN (?:RSA |DSA |EC )?ENCRYPTED PRIVATE KEY-----
```

**Reference**: <https://man.openbsd.org/ssh-keygen.1>

**Input that fires** (verified by the liveness test):

```text
-----BEGIN RSA ENCRYPTED PRIVATE KEY-----
```

### rsa-private-key

RSA Private Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | allowed |
| Tags | `rsa`, `private-key`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
-----BEGIN RSA PRIVATE KEY-----
```

**Reference**: <https://man.openbsd.org/ssh-keygen.1>

**Input that fires** (verified by the liveness test):

```text
-----BEGIN RSA PRIVATE KEY-----
```

### secrets-aws-access-key

AWS Access Key ID detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3.5` |
| Tags | `aws`, `cloud`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
AKIA[0-9A-Z]{16}
```

**Reference**: <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
AKIAB3D7…P6
```

### secrets-aws-secret-key

AWS Secret Access Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `aws`, `cloud`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]
```

**Reference**: <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
aws_secret = "wJalrXUt…MI/K7MDENGb…kN"
```

### secrets-github-token

GitHub Token detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `github`, `token`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
gh[pousr]_[A-Za-z0-9_]{36,}
```

**Reference**: <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-tokens>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
ghu_dkcm…bV
```

### secrets-sendgrid-api-key

SendGrid API Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `sendgrid`, `email`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}
```

**Reference**: <https://docs.sendgrid.com/api-reference/api-key-permissions>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
SG.ievHz8RB…T7.rHV23uvE…WL
```

### secrets-slack-token

Slack Token detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `slack`, `token`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*
```

**Reference**: <https://api.slack.com/authentication/token-types>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
xoxa-732…xm
```

### secrets-stripe-api-key

Stripe API Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `stripe`, `payment`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
sk_live_[0-9a-zA-Z]{24}
```

**Reference**: <https://stripe.com/docs/keys>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
sk_live_…Yb
```

### secrets-stripe-publishable-key

Stripe Publishable Key detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4.5` |
| Tags | `stripe`, `payment`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
pk_live_[0-9a-zA-Z]{24}
```

**Reference**: <https://stripe.com/docs/keys>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
pk_live_…eh
```

### secrets-twilio-api-key

Twilio API Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `3.5` |
| Tags | `twilio`, `sms`, `api-key` |

**Match pattern** (Rust `regex` syntax):

```regex
SK[0-9a-fA-F]{32}
```

**Reference**: <https://www.twilio.com/docs/iam/keys>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
SK9f26C4…ea
```

### ssh-private-key

SSH Private Key detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | allowed |
| Tags | `ssh`, `private-key`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----
```

**Reference**: <https://man.openbsd.org/ssh-keygen.1>

**Input that fires** (verified by the liveness test):

```text
-----BEGIN OPENSSH PRIVATE KEY-----
```

### twitter-api-key

Twitter API Key detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `medium` |
| Scope | `environment` — runs only during `aegis scan --env` |
| Applies to | every text file |
| Binary files | skipped |
| Entropy floor | `4` |
| Tags | `twitter`, `api`, `credential` |

**Match pattern** (Rust `regex` syntax):

```regex
[A-Za-z0-9]{25,}
```

**Reference**: <https://developer.twitter.com/en/docs/authentication/oauth-1-0a>

**Environment value that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Td9w75ue…8R
```
