# Secrets Scanner — Claude Code Skill

> A Claude Code skill that scans your entire codebase for hardcoded secrets, credentials, API keys, and sensitive data — before they reach GitHub.

Built specifically for DevOps engineers, platform engineers, and developers who work with Infrastructure as Code, multi-cloud environments, and automated pipelines.

---

## The Problem

Every day, DevOps engineers write Terraform modules, Terragrunt configurations, Helm charts, Kubernetes manifests, Ansible playbooks, and CI/CD pipelines. In the middle of that work — under deadline pressure, in a rush to test something, or simply out of habit — secrets end up hardcoded directly in files:

```hcl
# terraform/provider.tf
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region     = "us-east-1"
}
```

```yaml
# k8s/deployment.yaml
env:
  - name: DB_PASSWORD
    value: "prod-super-secret-password-123"
```

```python
# app/config.py
STRIPE_SECRET_KEY = "sk_live_<YOUR_STRIPE_KEY>"
```

Once that code is pushed to GitHub — even to a private repository — the secret is exposed. Git history is permanent. Bots scan public repositories continuously. A leaked AWS key can result in a six-figure cloud bill within hours. A leaked database password can expose customer data. A leaked Stripe key can drain revenue.

**The root cause is not carelessness. It is the absence of a fast, intelligent check in the developer's workflow.**

---

## Why Existing Tools Fall Short

| Tool | Limitation |
|------|-----------|
| `grep` / manual review | No intelligence — misses context, generates noise, not scalable |
| `trufflehog` / `gitleaks` | Great for post-commit scanning, but require separate installation and setup per machine |
| IDE plugins | Only cover the file open in editor, miss cross-file patterns |
| GitHub secret scanning | Runs after the push — too late for private repos or self-hosted Git |
| CI pipeline scanners | Only catch secrets after code is already committed and pushed |

None of these integrate directly into the moment a DevOps engineer is actively writing and reviewing code. That is the gap this skill fills.

---

## What This Skill Does

The Secrets Scanner is a Claude Code skill — a natural language command you invoke from inside your terminal while you work. When called, it:

1. **Scans your entire codebase** using pattern-matched grep across 25 categories covering every major platform and IaC tool
2. **Applies intelligent analysis** — Claude distinguishes real secrets from placeholder values, variable references, and dummy data that other tools flag as false positives
3. **Reports findings by severity** — CRITICAL, HIGH, MEDIUM, LOW — with the exact file, line number, secret type, and platform
4. **Gives you concrete remediation** — not just "this is a secret" but exactly how to fix it for that specific tool (Terraform, Kubernetes, Ansible, etc.)

All of this happens in seconds, inside your existing Claude Code session, with no additional tools to install.

---

## Who This Is For

This skill is designed for:

- **DevOps engineers** building and maintaining infrastructure across AWS, GCP, Azure, and other cloud platforms
- **Platform engineers** managing Terraform modules, Terragrunt configurations, and Helm chart libraries
- **Cloud architects** reviewing IaC pull requests for security compliance
- **Security engineers** conducting pre-merge audits of infrastructure code
- **Backend developers** who write application code that connects to cloud services and databases
- **Anyone** who wants a fast, intelligent secrets check before running `git push`

---

## The Workflow

### Without this skill

```
Write IaC / app code
       ↓
git add . && git push          ← secret committed here
       ↓
CI pipeline runs
       ↓
Secret scanner alerts (if configured)   ← too late
       ↓
Rotate credentials, audit access logs, write incident report
```

### With this skill

```
Write IaC / app code
       ↓
/secrets-scanner        ← catch it here, before commit
       ↓
Review report — fix flagged files
       ↓
git add . && git push          ← clean code
       ↓
CI pipeline runs — no secrets to find
```

The shift is from **reactive** (detect after exposure) to **proactive** (detect during development).

---

## Installation

### Prerequisites

- [Claude Code](https://claude.ai/code) installed (`npm install -g @anthropic-ai/claude-code`)
- A Claude account

### One-line install

```bash
mkdir -p ~/.claude/commands && \
curl -fsSL https://raw.githubusercontent.com/goku-70/secrets-scanner-skill/main/skills/secrets-scanner/SKILL.md \
  -o ~/.claude/commands/secrets-scanner.md
```

That is it. The skill is now available as `/secrets-scanner` in every Claude Code session across all your projects.

---

## Usage

Open Claude Code in any project directory and call the skill:

### Scan the entire current directory
```
/secrets-scanner
```

### Scan a specific path
```
/secrets-scanner ./infrastructure
```

### Scan a Terraform module before raising a PR
```
/secrets-scanner ./terraform/modules/rds
```

### Scan a Helm chart before deploying
```
/secrets-scanner ./charts/backend-api
```

### Scan only Kubernetes manifests
```
/secrets-scanner ./k8s
```

### Scan the full repo from root
```
/secrets-scanner .
```

---

## What Gets Scanned

### Cloud Platforms

| Platform | Credentials Detected |
|----------|---------------------|
| **AWS** | Access Keys (`AKIA*`, `ASIA*`), Secret Access Keys, Session Tokens, CloudFormation hardcoded params |
| **GCP** | API Keys (`AIza*`), OAuth Tokens (`ya29.*`), Service Account JSON files, private key IDs |
| **Azure** | Storage connection strings, Account Keys, SAS Tokens, Client Secrets, Bicep insecure params |
| **DigitalOcean** | Personal Access Tokens (`dop_v1_*`) |
| **Oracle Cloud** | OCIDs, API private keys |
| **IBM Cloud** | Platform API Keys |
| **Alibaba Cloud** | AccessKey ID and AccessKey Secret |
| **Cloudflare** | API Tokens, Global API Keys |

### IaC Tools

| Tool | What Gets Flagged |
|------|-----------------|
| **Terraform** | Hardcoded provider credentials, resource passwords, committed `.tfvars` files, state files with secrets, variables missing `sensitive = true` |
| **Terragrunt** | Hardcoded values in `terragrunt.hcl`, `.terragrunt-cache` accidentally committed |
| **Pulumi** | Hardcoded cloud credentials in stack programs, `config.require()` used instead of `config.requireSecret()` |
| **AWS CDK** | `SecretValue.unsafePlainText()`, hardcoded access keys inside stack constructs |
| **CloudFormation** | Secret `Default` values in parameters with `NoEcho: true`, plaintext resource credentials |
| **Helm** | `values.yaml`, `values-*.yaml`, `secrets.yaml` with plaintext passwords or tokens |
| **Kubernetes** | `kind: Secret` with `stringData`, hardcoded `env.value` for sensitive env vars in Deployments and StatefulSets |
| **Ansible** | `ansible_password`, `ansible_ssh_pass`, `ansible_become_pass`, vault tokens in plaintext playbooks or inventory |
| **Azure Bicep** | Parameters missing `@secure()` decorator, `Default` values set on secret parameters |

### CI/CD Pipelines

| Platform | What Gets Flagged |
|----------|-----------------|
| **GitHub Actions** | Hardcoded `value:` assignments in workflow env blocks without `${{ secrets.* }}` |
| **GitLab CI** | Plaintext `password:` or `token:` values not using `$CI_*` variables |
| **CircleCI** | Credentials in `.circleci/config.yml` |
| **Jenkins** | Hardcoded strings in `Jenkinsfile` env blocks |
| **Bitbucket Pipelines** | Plaintext credentials in `bitbucket-pipelines.yml` |

### Application Code & Config

- **Private keys** — RSA, EC, OpenSSH, DSA, PGP
- **JWT tokens** — embedded in source code or config files
- **Database DSNs** — PostgreSQL, MySQL, MongoDB, Redis, RabbitMQ, JDBC, SQL Server connection strings with passwords
- **`.env` files** — any real value assignments (ignores placeholder patterns)
- **Docker Compose** — hardcoded env var values in `docker-compose.yml`
- **Source control tokens** — GitHub (`ghp_*`, `gho_*`), GitLab (`glpat-*`), Bitbucket, Terraform Cloud
- **HashiCorp Vault tokens** — `hvs.*` live tokens committed to code
- **SaaS keys** — Slack (`xoxb-*`, `xoxp-*`), Stripe live keys (`sk_live_*`), Twilio, SendGrid, Datadog, PagerDuty, Databricks, Snowflake

---

## Example Report

```
## Secrets Scan Report

Scanned path: ./infrastructure
IaC tools detected: Terraform, Terragrunt, Helm, Kubernetes, GitHub Actions
Total findings: 6 — 1 CRITICAL · 2 HIGH · 2 MEDIUM · 1 LOW

### CRITICAL
| # | File                      | Line | Secret Type    | Platform  | Value (masked)        | Remediation                              |
|---|---------------------------|------|----------------|-----------|-----------------------|------------------------------------------|
| 1 | terraform/provider.tf     | 8    | AWS Access Key | AWS       | AKIA**************    | Use IAM role or TF_VAR_ environment var  |

### HIGH
| # | File                      | Line | Secret Type    | Platform   | Value (masked)           | Remediation                          |
|---|---------------------------|------|----------------|------------|--------------------------|--------------------------------------|
| 1 | .env                      | 3    | GitHub Token   | GitHub     | ghp_***************      | Rotate now, move to GitHub Secrets   |
| 2 | k8s/deployment.yaml       | 44   | DB Password    | PostgreSQL | postgres://app:***@host  | Use secretKeyRef in manifest         |

### MEDIUM
| # | File                      | Line | Secret Type        | Platform   | Value (masked)  | Remediation                              |
|---|---------------------------|----|---------------------|------------|-----------------|------------------------------------------|
| 1 | charts/values.yaml        | 12   | Hardcoded password | Helm       | mysql-***       | Use helm-secrets + SOPS encryption       |
| 2 | .github/workflows/ci.yml  | 31   | API key in env     | GitHub Actions | sk_live_*** | Move to repository secrets               |

### LOW
| # | File                      | Line | Secret Type            | Platform  | Value (masked)    | Remediation                   |
|---|---------------------------|------|------------------------|-----------|-------------------|-------------------------------|
| 1 | terraform/variables.tf    | 5    | Missing sensitive=true | Terraform | var.db_password   | Add sensitive = true to block |

### False Positives Dismissed
- terraform/examples/provider.tf:12 — value "REPLACE_WITH_YOUR_KEY" is a placeholder
- ansible/group_vars/all.yml:8 — value "${VAULT_PASSWORD}" is a variable reference

### Remediation Guide

**AWS**
Replace hardcoded keys with IAM instance roles. In Terraform, use:
  - Environment variables: TF_VAR_access_key
  - Or the aws_secretsmanager_secret data source

**Kubernetes**
Replace env.value with:
  valueFrom:
    secretKeyRef:
      name: my-secret
      key: password

**Helm**
Encrypt values.yaml using helm-secrets + SOPS:
  helm secrets enc charts/values.yaml

[... full per-platform remediation ...]
```

---

## How It Works Internally

```
User runs: /secrets-scanner ./infrastructure
                        │
                        ▼
          ┌─────────────────────────────┐
          │  Shell injection (pre-scan) │
          │  25 grep sections run       │
          │  against the target path    │
          └────────────┬────────────────┘
                       │  raw matches
                       ▼
          ┌─────────────────────────────┐
          │  Claude intelligent layer   │
          │                             │
          │  • Filter false positives   │
          │    (placeholders, var refs) │
          │  • Classify by severity     │
          │  • Identify platform/tool   │
          │  • Map remediation per tool │
          └────────────┬────────────────┘
                       │
                       ▼
          Structured report with masked
          values, severity, and fixes
```

The skill runs grep patterns for every known secret format before Claude even processes the results. Claude then applies contextual intelligence to filter out noise — something pattern-only tools cannot do — and produces a report tailored to the specific IaC tools and platforms present in the scanned directory.

---

## Severity Levels

| Level | Meaning | Immediate action required? |
|-------|---------|---------------------------|
| **CRITICAL** | Cloud provider keys, private keys, Vault tokens, Terraform state with credentials | Yes — rotate immediately |
| **HIGH** | Source control tokens, live payment keys, database DSNs with real passwords, K8s Secret manifests | Yes — rotate and remediate |
| **MEDIUM** | Hardcoded passwords in IaC resources, Helm values, CI/CD pipelines, `.env` files | Fix before merging |
| **LOW** | Missing `sensitive = true`, suspicious variable names, committed `.tfvars` | Fix before release |

---

## After a CRITICAL or HIGH Finding

If the scanner finds a real secret that may have already been committed:

1. **Treat it as compromised immediately** — assume it has been seen even if the repo is private
2. **Rotate the credential** in the originating platform (AWS IAM, GitHub Settings, Stripe Dashboard, etc.)
3. **Remove it from git history** — use `git filter-repo` or BFG Repo Cleaner
4. **Audit access logs** — check the platform's audit trail for unexpected usage during the window of exposure
5. **Add the secret type to your `.gitignore`** and pre-commit hooks to prevent recurrence

---

## Setting Up Prevention

After scanning, set up these guardrails so secrets cannot be committed in the first place:

### .gitignore — add these entries
```gitignore
# Terraform
*.tfvars
terraform.tfvars
*.auto.tfvars
terraform.tfstate
terraform.tfstate.backup
.terraform/
.terragrunt-cache/
.terraformrc

# Environment
.env
.env.*
env.local
*.env

# Credentials and keys
*.pem
*.key
*.p12
*.pfx
*.jks
service-account*.json
credentials.json
```

### Pre-commit hook with gitleaks (recommended for IaC repos)
```bash
brew install gitleaks
```

Add `.pre-commit-config.yaml` to your repo:
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

Install the hook:
```bash
pip install pre-commit
pre-commit install
```

### Terraform — always declare secrets as sensitive
```hcl
variable "db_password" {
  type        = string
  sensitive   = true
  description = "RDS master password — inject via TF_VAR_db_password"
}
```

### Kubernetes — always reference secrets, never inline them
```yaml
# Wrong
env:
  - name: DB_PASSWORD
    value: "hardcoded-password"

# Correct
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: app-secrets
        key: db-password
```

### Ansible — encrypt with ansible-vault
```bash
ansible-vault encrypt_string 'my-secret-value' --name 'db_password'
```

### Helm — use helm-secrets with SOPS
```bash
helm plugin install https://github.com/jkroepke/helm-secrets
helm secrets enc charts/values-prod.yaml
```

---

## Alternative Installation Methods

### Direct GitHub install (no marketplace)
```bash
claude plugin install github://goku-70/secrets-scanner-skill
```

### Fork and customise for your organisation
Fork this repo, add your own internal secret patterns to `SKILL.md`, then install from your fork:
```bash
claude plugin install github://your-org/secrets-scanner-skill
```

### Embed directly in a project
Copy the skill into your own repo so the whole team gets it without installing anything:
```bash
mkdir -p .claude/skills/secrets-scanner
curl -o .claude/skills/secrets-scanner/SKILL.md \
  https://raw.githubusercontent.com/goku-70/secrets-scanner-skill/main/skills/secrets-scanner/SKILL.md
```

Commit `.claude/skills/` to your repo. Everyone who opens Claude Code in the project gets the skill automatically.

---

## Repository Structure

```
secrets-scanner-skill/
├── .claude-plugin/
│   └── plugin.json                        # Plugin identity and metadata
├── skills/
│   └── secrets-scanner/
│       ├── SKILL.md                       # Core skill — all scan logic and report format
│       └── patterns.md                    # Full reference for all detected secret patterns
├── marketplace.json                        # Enables one-command installation
├── README.md                              # This file
├── .gitignore
└── LICENSE                                # MIT
```

---

## Contributing

Contributions are welcome — especially additions for:
- New cloud provider credential formats
- Additional IaC tool patterns
- New SaaS API key formats
- Improved false positive filtering rules

To add a new scan pattern, edit `skills/secrets-scanner/SKILL.md` and add a corresponding entry to `skills/secrets-scanner/patterns.md`. Open a pull request with a description of what the new pattern detects and a non-sensitive example.

---

## License

MIT — free to use, fork, and embed in your own projects or organisations.
