---
name: secrets-scanner
description: Scans codebases for hardcoded secrets, credentials, API keys, tokens, and sensitive data across all IaC tools (Terraform, Terragrunt, Pulumi, CloudFormation, Ansible, Helm, Kubernetes, CDK, Bicep) and all cloud platforms (AWS, GCP, Azure, DigitalOcean, Oracle Cloud, IBM Cloud, Alibaba Cloud, Cloudflare). Also covers CI/CD pipelines, databases, SaaS APIs, and application code. Use before pushing code to GitHub or when auditing infrastructure configurations for exposed credentials.
when_to_use: "scan for secrets, find hardcoded credentials, check for API keys, audit IaC for sensitive data, pre-commit security check, scan terraform for secrets, scan codebase for tokens, check kubernetes manifests, audit ansible playbooks, scan helm charts, check cloudformation templates, scan pulumi code, check bicep files, check github actions for secrets"
argument-hint: "[path] (optional — defaults to current directory)"
allowed-tools: Bash(grep *) Bash(find *) Bash(git log *) Bash(git diff *) Bash(git status *) Read Glob
---

# Secrets Scanner

You are a security-focused secrets scanner. Your job is to detect hardcoded secrets, credentials, API keys, tokens, and sensitive data across all IaC tools and cloud platforms.

## Scan Target

The scan path is: **$ARGUMENTS**
If no path was provided, use `.` (current directory).

**IMPORTANT — path substitution rule:** In every Bash command below, replace the literal text `SCAN_PATH` with the actual scan path (e.g. `.` or `/Users/me/project`). Never use shell variables like `$TARGET` or `${TARGET}` — always inline the literal path string directly into each command.

## Step 1 — Run All Scans

Use the Bash tool to run each grep/find command below. Collect all output. Do NOT skip any section.

---

### A1 — Generic credential assignments (all file types)

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "password\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "passwd\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "secret\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "secret_key\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "api_key\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "apikey\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "auth_token\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "access_token\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "private_key\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "encryption_key\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "signing_key\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  -e "master_key\s*=\s*['\"][^'\"]\{4,\}['\"]" \
  --include="*.tf" --include="*.tfvars" --include="*.hcl" \
  --include="*.yaml" --include="*.yml" --include="*.json" \
  --include="*.toml" --include="*.ini" --include="*.env" \
  --include="*.py" --include="*.js" --include="*.ts" \
  --include="*.go" --include="*.java" --include="*.rb" \
  --include="*.php" --include="*.sh" --include="*.conf" \
  --include="*.xml" --include="*.bicep" \
  --exclude-dir=".git" --exclude-dir="node_modules" \
  --exclude-dir=".terraform" --exclude-dir="vendor" \
  --exclude-dir=".terragrunt-cache" \
  SCAN_PATH 2>/dev/null || true
```

### A2 — Private keys and certificates

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "-----BEGIN RSA PRIVATE KEY-----" \
  -e "-----BEGIN EC PRIVATE KEY-----" \
  -e "-----BEGIN OPENSSH PRIVATE KEY-----" \
  -e "-----BEGIN DSA PRIVATE KEY-----" \
  -e "-----BEGIN PRIVATE KEY-----" \
  -e "-----BEGIN PGP PRIVATE KEY BLOCK-----" \
  --exclude-dir=".git" --exclude-dir="node_modules" \
  --exclude-dir=".terraform" --exclude-dir=".terragrunt-cache" \
  SCAN_PATH 2>/dev/null || true
```

### A3 — JWT tokens

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "eyJ[A-Za-z0-9_-]\{30,\}\.[A-Za-z0-9_-]\{30,\}\.[A-Za-z0-9_-]\{10,\}" \
  --exclude-dir=".git" --exclude-dir="node_modules" \
  SCAN_PATH 2>/dev/null || true
```

---

### B1 — AWS access keys

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "AKIA[0-9A-Z]\{16\}" \
  -e "ASIA[0-9A-Z]\{16\}" \
  -e "aws_secret_access_key\s*=\s*['\"][^'\"]\{16,\}['\"]" \
  -e "AWS_ACCESS_KEY_ID\s*=\s*[A-Z0-9]\{16,\}" \
  -e "AWS_SECRET_ACCESS_KEY\s*=\s*[A-Za-z0-9/+=]\{30,\}" \
  --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir=".terraform" \
  SCAN_PATH 2>/dev/null || true
```

### B2 — AWS in Terraform provider blocks

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "access_key\s*=\s*\"[^\"]\{10,\}\"" \
  -e "secret_key\s*=\s*\"[^\"]\{10,\}\"" \
  --include="*.tf" --include="*.tfvars" --include="*.hcl" \
  --exclude-dir=".git" --exclude-dir=".terraform" --exclude-dir=".terragrunt-cache" \
  SCAN_PATH 2>/dev/null || true
```

---

### C1 — GCP credentials

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "AIza[0-9A-Za-z_-]\{35\}" \
  -e "ya29\.[0-9A-Za-z_-]\{60,\}" \
  -e "\"type\"\s*:\s*\"service_account\"" \
  -e "GOOGLE_API_KEY\s*=\s*['\"][^'\"]\{10,\}['\"]" \
  --exclude-dir=".git" --exclude-dir="node_modules" \
  SCAN_PATH 2>/dev/null || true
```

---

### D1 — Azure credentials

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "AccountKey=[A-Za-z0-9+/=]\{40,\}" \
  -e "DefaultEndpointsProtocol=https;AccountName=" \
  -e "SharedAccessSignature=sv=" \
  -e "AZURE_CLIENT_SECRET\s*=\s*['\"][^'\"]\{10,\}['\"]" \
  -e "AZURE_STORAGE_KEY\s*=\s*['\"][^'\"]\{10,\}['\"]" \
  --exclude-dir=".git" --exclude-dir="node_modules" \
  SCAN_PATH 2>/dev/null || true
```

---

### E1 — Other cloud providers (DigitalOcean, IBM, Alibaba, Cloudflare)

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "dop_v1_[a-f0-9]\{64\}" \
  -e "DIGITALOCEAN_TOKEN\s*=\s*['\"][^'\"]\{60,\}['\"]" \
  -e "IBMCLOUD_API_KEY\s*=\s*['\"][^'\"]\{30,\}['\"]" \
  -e "ALICLOUD_ACCESS_KEY\s*=\s*['\"][^'\"]\{16,\}['\"]" \
  -e "CLOUDFLARE_API_TOKEN\s*=\s*['\"][^'\"]\{30,\}['\"]" \
  --exclude-dir=".git" --exclude-dir="node_modules" \
  SCAN_PATH 2>/dev/null || true
```

---

### F1 — Terraform/Terragrunt sensitive files

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
find SCAN_PATH \( -name "terraform.tfvars" -o -name "*.auto.tfvars" -o -name "*.tfvars" -o -name "terraform.tfstate" -o -name "terraform.tfstate.backup" -o -name ".terraformrc" \) -not -path "*/.git/*" -not -path "*/.terraform/*" 2>/dev/null || true
```

### F2 — Terraform variables missing sensitive=true

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "variable\s*\"[^\"]*password[^\"]*\"" \
  -e "variable\s*\"[^\"]*secret[^\"]*\"" \
  -e "variable\s*\"[^\"]*token[^\"]*\"" \
  -e "variable\s*\"[^\"]*key[^\"]*\"" \
  --include="*.tf" \
  --exclude-dir=".git" --exclude-dir=".terraform" \
  SCAN_PATH 2>/dev/null || true
```

### F3 — Kubernetes secrets and hardcoded env vars

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "kind\s*:\s*Secret" \
  -e "stringData\s*:" \
  --include="*.yaml" --include="*.yml" \
  --exclude-dir=".git" \
  SCAN_PATH 2>/dev/null || true
```

### F4 — Helm values with hardcoded secrets

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
find SCAN_PATH \( -name "values.yaml" -o -name "values-*.yaml" -o -name "secrets.yaml" \) -not -path "*/.git/*" -exec grep -Hn -e "password\s*:" -e "token\s*:" -e "secret\s*:" {} \; 2>/dev/null || true
```

### F5 — Ansible plaintext credentials

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "ansible_password\s*:\s*['\"][^'\"]\{4,\}['\"]" \
  -e "ansible_ssh_pass\s*:\s*['\"][^'\"]\{4,\}['\"]" \
  -e "ansible_become_pass\s*:\s*['\"][^'\"]\{4,\}['\"]" \
  -e "vault_token\s*:\s*['\"][^'\"]\{4,\}['\"]" \
  --include="*.yaml" --include="*.yml" --include="*.ini" \
  --exclude-dir=".git" \
  SCAN_PATH 2>/dev/null || true
```

### F6 — GitHub Actions hardcoded secrets

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
find SCAN_PATH -path "*/.github/workflows/*.yml" -not -path "*/.git/*" -exec grep -Hn -e "value\s*:\s*['\"][^'\"]\{8,\}['\"]" {} \; 2>/dev/null | grep -v "\${{" || true
```

---

### G1 — Source control and DevOps tokens

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "gh[pos]_[A-Za-z0-9]\{36\}" \
  -e "glpat-[A-Za-z0-9_-]\{20\}" \
  -e "hvs\.[A-Za-z0-9_-]\{90,\}" \
  -e "TFE_TOKEN\s*=\s*['\"][^'\"]\{10,\}['\"]" \
  --exclude-dir=".git" --exclude-dir="node_modules" \
  SCAN_PATH 2>/dev/null || true
```

---

### H1 — SaaS API keys

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "xox[bpa]-[0-9A-Za-z-]\{40,\}" \
  -e "sk_live_[0-9A-Za-z]\{24,\}" \
  -e "dapi[A-Za-z0-9]\{32\}" \
  -e "DATADOG_API_KEY\s*=\s*[a-f0-9]\{32\}" \
  -e "SG\.[A-Za-z0-9_-]\{22\}\.[A-Za-z0-9_-]\{40,\}" \
  --exclude-dir=".git" --exclude-dir="node_modules" \
  SCAN_PATH 2>/dev/null || true
```

---

### I1 — Database connection strings

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
grep -rn \
  -e "postgres://[^:]*:[^@]\{4,\}@" \
  -e "postgresql://[^:]*:[^@]\{4,\}@" \
  -e "mysql://[^:]*:[^@]\{4,\}@" \
  -e "mongodb[+a-z]*://[^:]*:[^@]\{4,\}@" \
  -e "redis://[^:]*:[^@]\{4,\}@" \
  -e "amqp://[^:]*:[^@]\{4,\}@" \
  --exclude-dir=".git" --exclude-dir="node_modules" \
  SCAN_PATH 2>/dev/null || true
```

---

### J1 — .env and Docker Compose files

Run this Bash command (replace `SCAN_PATH` with the actual path):
```
find SCAN_PATH \( -name ".env" -o -name "*.env" -o -name ".env.*" \) -not -path "*/.git/*" -not -path "*/node_modules/*" -exec grep -Hn "=.\{4,\}" {} \; 2>/dev/null | grep -v "#\|=your_\|=<\|=CHANGE\|=REPLACE\|=TODO\|=example\|=test\|=\${" || true
```

---

## Step 2 — Intelligent Analysis

For every match found, apply this logic:

**Dismiss as false positive if the value contains:**
- Placeholders: `your_key_here`, `<YOUR_*>`, `REPLACE_ME`, `CHANGEME`, `TODO`
- Dummy values: `example`, `test`, `sample`, `fake`, `dummy`, `mock`
- Repeated chars: `xxxxxxxx`, `00000000`, `11111111`
- Variable references: `$VAR`, `${VAR}`, `var.something`, `data.something`
- CI references: `${{ secrets.* }}`, `$CI_*`, `$GITHUB_*`
- Empty strings or values under 6 characters

**Assign severity:**
- `CRITICAL` — Cloud provider keys (AWS/GCP/Azure/OCI/IBM/Alibaba), private keys, Vault tokens, Terraform state files
- `HIGH` — GitHub/GitLab tokens, Stripe live keys, Slack tokens, database DSNs with real passwords, Kubernetes Secret manifests
- `MEDIUM` — Hardcoded passwords in IaC resources, Helm values, Ansible plaintext, .env files, committed .tfvars
- `LOW` — Variables missing `sensitive = true`, suspicious assignments needing review

---

## Step 3 — Report

Output in this format:

---

## Secrets Scan Report

**Scanned path:** `<path>`
**IaC tools detected:** `<list what was found>`
**Total findings:** `<N>` — `<critical>` CRITICAL · `<high>` HIGH · `<medium>` MEDIUM · `<low>` LOW

---

### CRITICAL

| # | File | Line | Secret Type | Platform | Value (masked) | Remediation |
|---|------|------|-------------|----------|----------------|-------------|
| 1 | `path/to/file.tf` | 8 | AWS Access Key | AWS | `AKIA************` | Use IAM role or TF_VAR_ env var |

### HIGH
_(same table)_

### MEDIUM
_(same table)_

### LOW
_(same table)_

---

### False Positives Dismissed
_(one line each — what it was and why dismissed)_

---

### Remediation by Platform

Only include sections relevant to what was found:

**AWS** — Use IAM roles or `TF_VAR_` env vars. Never hardcode keys in `.tf` or pipeline files.
**GCP** — Use Workload Identity Federation. Store SA keys in Secret Manager.
**Azure** — Use Managed Identity. Store secrets in Azure Key Vault.
**Terraform/Terragrunt** — Add `sensitive = true` to secret variables. Add `*.tfvars`, `*.tfstate` to `.gitignore`.
**Kubernetes** — Replace `env.value` with `secretKeyRef`. Use Sealed Secrets or External Secrets Operator.
**Helm** — Use `helm-secrets` + SOPS for values files.
**Ansible** — Use `ansible-vault encrypt_string` for passwords.
**CI/CD** — Move all credentials to platform secrets. Reference as `${{ secrets.MY_SECRET }}`.

---

### Next Steps

1. Rotate any CRITICAL or HIGH secrets immediately — treat them as compromised.
2. Add a pre-commit hook: `brew install gitleaks && gitleaks protect --staged`
3. Add `*.tfvars`, `.env`, `*.pem`, `*.key`, `terraform.tfstate` to `.gitignore`.

---

If no real secrets are found, output:

**No hardcoded secrets detected.** The codebase appears clean. Consider adding a pre-commit hook as a preventive measure.
