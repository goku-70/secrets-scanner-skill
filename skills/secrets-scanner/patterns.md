# Secret Patterns Reference

Full reference for all secret patterns the scanner detects, organised by platform and tool.

---

## Cloud Providers

### AWS
| Secret Type | Pattern / Indicator | Notes |
|-------------|-------------------|-------|
| Access Key ID | `AKIA[0-9A-Z]{16}` | Static long-term key |
| Assumed Role Key | `ASIA[0-9A-Z]{16}` | Temporary STS key |
| Role ID | `AROA[0-9A-Z]{16}` | Role-based key |
| IAM User ID | `AIDA[0-9A-Z]{16}` | IAM user ID |
| Secret Access Key | 40-char base64 string beside `aws_secret_access_key` | Always rotate if found |
| Session Token | Long base64 beside `aws_session_token` | Short-lived but dangerous |

### GCP / Google Cloud
| Secret Type | Pattern / Indicator | Notes |
|-------------|-------------------|-------|
| API Key | `AIza[0-9A-Za-z\-\_]{35}` | 39 chars total |
| OAuth Access Token | `ya29.[0-9A-Za-z\-\_]{60+}` | Starts with ya29. |
| Service Account JSON | `"type": "service_account"` + `"private_key"` | Full JSON file — CRITICAL |
| Private Key ID | 40-char hex beside `"private_key_id"` | Part of SA JSON |

### Azure
| Secret Type | Pattern / Indicator | Notes |
|-------------|-------------------|-------|
| Storage connection string | `DefaultEndpointsProtocol=https;AccountName=...;AccountKey=` | Often in app configs |
| Storage Account Key | `AccountKey=[A-Za-z0-9+/=]{40+}` | |
| SAS Token | `SharedAccessSignature=sv=` | |
| Client Secret | UUID-format value beside `client_secret` | App Registration secret |
| Storage access key in Terraform | `storage_account_access_key = "..."` | |

### DigitalOcean
| Secret Type | Pattern / Indicator | Notes |
|-------------|-------------------|-------|
| Personal Access Token | `dop_v1_[a-f0-9]{64}` | 64-char hex |
| Legacy token | `do_token = "..."` in `.tf` files | |

### Oracle Cloud (OCI)
| Secret Type | Pattern / Indicator | Notes |
|-------------|-------------------|-------|
| OCID | `ocid1.[resource_type].[realm]...` | Resource identifier — sensitive |
| API Private Key | PEM key beside `oci_private_key` | |

### IBM Cloud
| Secret Type | Pattern / Indicator | Notes |
|-------------|-------------------|-------|
| API Key | 40+ char value beside `IBMCLOUD_API_KEY` or `IC_API_KEY` | |

### Alibaba Cloud
| Secret Type | Pattern / Indicator | Notes |
|-------------|-------------------|-------|
| Access Key ID | 20-char alphanumeric beside `access_key_id` | |
| Access Key Secret | 30-char value beside `access_key_secret` | |

### Cloudflare
| Secret Type | Pattern / Indicator | Notes |
|-------------|-------------------|-------|
| API Token | 40+ char beside `CLOUDFLARE_API_TOKEN` | Scoped token |
| Global API Key | 37-char hex beside `cloudflare_api_key` | Full account access |

---

## IaC Tools

### Terraform / Terragrunt
| Risk | What to look for |
|------|-----------------|
| Hardcoded provider credentials | `access_key`, `secret_key`, `token` with literal string values |
| Hardcoded resource passwords | `password = "actual_value"` in `aws_db_instance`, `azurerm_sql_server`, etc. |
| Missing `sensitive = true` | Variable block for secret without `sensitive = true` |
| Committed `.tfvars` | `terraform.tfvars`, `*.auto.tfvars` present in repo |
| Committed state file | `terraform.tfstate` — contains all resource attribute values |
| Committed `.terraformrc` | May contain Terraform Cloud token |
| Terragrunt cache | `.terragrunt-cache/` — should never be committed |

### Pulumi
| Risk | What to look for |
|------|-----------------|
| Plaintext secret in config | `pulumi config set myKey value` without `--secret` flag |
| Hardcoded cloud credentials | `aws.config.accessKey = "..."` in program code |
| `config.require()` for secrets | Should be `config.requireSecret()` |
| Stack config with `ciphertext` | `Pulumi.*.yaml` with encrypted values — key management matters |

### AWS CDK
| Risk | What to look for |
|------|-----------------|
| `SecretValue.unsafePlainText()` | Hardcoded secret in CDK stack — CRITICAL |
| `SecretValue.plainText()` | Deprecated alias for above |
| Hardcoded `accessKeyId` / `secretAccessKey` | In CDK stack constructs |

### CloudFormation
| Risk | What to look for |
|------|-----------------|
| Parameter with `Default` + `NoEcho: true` | Secret value set as default — exposed in template |
| Hardcoded credentials in `Properties` | Literal values in resource definitions |
| `{{resolve:ssm-secure:...}}` vs plaintext | Ensure SSM Secure String is used |

### Kubernetes
| Risk | What to look for |
|------|-----------------|
| `kind: Secret` with `stringData` | Plaintext secrets in manifest files |
| `env.value` with sensitive name | `PASSWORD`, `TOKEN`, `SECRET` in `env` without `secretKeyRef` |
| Base64 in `data:` | Not encryption — just encoding. Still sensitive |

### Helm
| Risk | What to look for |
|------|-----------------|
| `values.yaml` with passwords | Literal values under `password:`, `token:`, `secret:` keys |
| Unencrypted `secrets.yaml` | Should use helm-secrets + SOPS |

### Ansible
| Risk | What to look for |
|------|-----------------|
| `ansible_password` plaintext | In inventory files or group_vars |
| `ansible_ssh_pass` | SSH password in plaintext |
| `vault_token` | HashiCorp Vault token in playbook |
| Unencrypted `group_vars/` | Should use `ansible-vault encrypt_string` |

### Azure Bicep
| Risk | What to look for |
|------|-----------------|
| `param` without `@secure()` | Secret parameter missing decorator |
| `Default` value on secret param | Never set defaults for passwords/keys |

---

## CI/CD Platforms

| Platform | Risk | What to look for |
|----------|------|-----------------|
| GitHub Actions | Hardcoded env var values | `value:` assignments without `${{ secrets.* }}` |
| GitLab CI | Plaintext variables | `password:` / `token:` without `$CI_*` reference |
| CircleCI | Env in config | Credentials in `.circleci/config.yml` |
| Jenkins | Credentials in Jenkinsfile | Hardcoded strings in `withCredentials` or `env` |
| Bitbucket Pipelines | Env vars | Plaintext in `bitbucket-pipelines.yml` |

---

## Source Control & DevOps Tokens

| Provider | Pattern | Prefix |
|----------|---------|--------|
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` | `ghp_` |
| GitHub OAuth App | `gho_[A-Za-z0-9]{36}` | `gho_` |
| GitHub App Installation | `ghs_[A-Za-z0-9]{36}` | `ghs_` |
| GitHub Refresh Token | `ghr_[A-Za-z0-9]{36}` | `ghr_` |
| GitLab PAT | `glpat-[A-Za-z0-9_-]{20}` | `glpat-` |
| Terraform Cloud | 40+ char beside `TFE_TOKEN` | |
| HashiCorp Vault | `hvs.[A-Za-z0-9_-]{90+}` | `hvs.` |

---

## SaaS APIs

| Service | Pattern | Notes |
|---------|---------|-------|
| Slack Bot Token | `xoxb-[0-9]{11}-...` | Full channel access |
| Slack User Token | `xoxp-...` | User-level access |
| Slack App Token | `xoxa-...` | App-level |
| Stripe Live Secret | `sk_live_[0-9a-z]{24+}` | Never commit |
| Stripe Restricted | `rk_live_[0-9a-z]{24+}` | |
| Stripe Publishable | `pk_live_[0-9a-z]{24+}` | Less critical but still sensitive |
| Twilio Account SID | `AC[0-9a-f]{32}` | |
| SendGrid | `SG.[A-Za-z0-9_-]{22}.[A-Za-z0-9_-]{43}` | |
| Datadog API Key | 32-char hex beside `DD_API_KEY` | |
| PagerDuty | 20+ char beside `PAGERDUTY_TOKEN` | |
| Databricks | `dapi[A-Za-z0-9]{32}` | Workspace token |

---

## Databases

| Type | DSN Pattern |
|------|-------------|
| PostgreSQL | `postgres://user:password@host` |
| MySQL | `mysql://user:password@host` |
| MongoDB | `mongodb://user:password@host` or `mongodb+srv://...` |
| Redis | `redis://:password@host` |
| RabbitMQ | `amqp://user:password@host` |
| SQL Server JDBC | `jdbc:sqlserver://...;password=value` |
| SQL Server ADO | `Server=...;Password=value` |

---

## Cryptographic Material

| Type | PEM Header |
|------|-----------|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` |
| OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| DSA Private Key | `-----BEGIN DSA PRIVATE KEY-----` |
| Generic Private Key | `-----BEGIN PRIVATE KEY-----` |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| JWT | `eyJ[base64].[base64].[base64]` — three-part dot-separated |

---

## False Positive Indicators

Dismiss a match if the value contains any of these — they are placeholders, not real secrets:

| Indicator | Examples |
|-----------|---------|
| Explicit placeholders | `your_key_here`, `<YOUR_API_KEY>`, `INSERT_HERE`, `REPLACE_ME` |
| Change directives | `CHANGEME`, `TODO`, `FIXME`, `UPDATE_THIS` |
| Example markers | `example`, `test`, `sample`, `fake`, `dummy`, `mock` |
| Repeated characters | `xxxxxxxx`, `00000000`, `11111111`, `aaaaaaaaa` |
| Variable references | `$VAR`, `${VAR_NAME}`, `%(var)s`, `{{variable}}` |
| Terraform references | `var.something`, `data.something`, `local.something` |
| CI variable references | `${{ secrets.* }}`, `$CI_*`, `$GITHUB_*` |
| Empty or trivially short | `""`, values under 6 characters |
| Pure dictionary words | `password`, `secret`, `mypassword` |
| Test/example directories | Paths containing `test/`, `examples/`, `sample/`, `docs/` |
