#!/usr/bin/env bash
# secrets-scanner — CI shell script
# Mirrors the grep patterns from the Claude Code skill.
# No API key or Claude Code installation required.
# Usage: ./scan.sh [path]   (defaults to current directory)

set -euo pipefail

TARGET="${1:-.}"
FINDINGS=0
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0
REPORT=""

RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

add_finding() {
  local severity="$1" file="$2" line="$3" type="$4" detail="$5"
  FINDINGS=$((FINDINGS + 1))
  case "$severity" in
    CRITICAL) CRITICAL=$((CRITICAL + 1)) ;;
    HIGH)     HIGH=$((HIGH + 1)) ;;
    MEDIUM)   MEDIUM=$((MEDIUM + 1)) ;;
    LOW)      LOW=$((LOW + 1)) ;;
  esac
  REPORT="${REPORT}[${severity}] ${file}:${line} — ${type}\n  ${detail}\n\n"
}

EXCLUDE='--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.terraform --exclude-dir=.terragrunt-cache --exclude-dir=vendor --exclude=*.md --exclude=scan.sh'

echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD}   Secrets Scanner — CI Scan${NC}"
echo -e "${BOLD}================================================${NC}"
echo "Scanning: ${TARGET}"
echo ""

# ── AWS ───────────────────────────────────────────────────────────────────────
echo "[ 1/11] AWS credentials..."

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "CRITICAL" "$file" "$line" "AWS Access Key ID" "AKIA* pattern detected"
done < <(grep -rn $EXCLUDE -e 'AKIA[0-9A-Z]\{16\}' "$TARGET" 2>/dev/null || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "CRITICAL" "$file" "$line" "AWS Secret Access Key" "aws_secret_access_key with literal value"
done < <(grep -rn $EXCLUDE \
  -e 'aws_secret_access_key\s*=\s*["'"'"'][^"'"'"']\{16,\}["'"'"']' \
  -e 'AWS_SECRET_ACCESS_KEY\s*:\s*[A-Za-z0-9/+=]\{30,\}' \
  "$TARGET" 2>/dev/null || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "CRITICAL" "$file" "$line" "AWS keys in CI pipeline" "Hardcoded AWS keys in workflow env block"
done < <(grep -rn $EXCLUDE \
  -e 'AWS_ACCESS_KEY_ID\s*:\s*[A-Z0-9]\{16,\}' \
  "$TARGET" 2>/dev/null || true)

# ── GCP ───────────────────────────────────────────────────────────────────────
echo "[ 2/11] GCP credentials..."

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "CRITICAL" "$file" "$line" "GCP API Key" "AIza* pattern detected"
done < <(grep -rn $EXCLUDE -e 'AIza[0-9A-Za-z_-]\{35\}' "$TARGET" 2>/dev/null || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "CRITICAL" "$file" "$line" "GCP Service Account JSON" "service_account type detected"
done < <(grep -rn $EXCLUDE -e '"type"\s*:\s*"service_account"' "$TARGET" 2>/dev/null || true)

# ── Azure ─────────────────────────────────────────────────────────────────────
echo "[ 3/11] Azure credentials..."

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "CRITICAL" "$file" "$line" "Azure Storage Account Key" "AccountKey detected in connection string"
done < <(grep -rn $EXCLUDE \
  -e 'AccountKey=[A-Za-z0-9+/=]\{40,\}' \
  -e 'DefaultEndpointsProtocol=https;AccountName=' \
  "$TARGET" 2>/dev/null || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "CRITICAL" "$file" "$line" "Azure Client Secret" "client_secret with literal value"
done < <(grep -rn $EXCLUDE \
  --include='*.tf' --include='*.tfvars' --include='*.bicep' --include='*.yml' --include='*.yaml' \
  -e 'AZURE_CLIENT_SECRET\s*=\s*["'"'"'][^"'"'"']\{8,\}["'"'"']' \
  "$TARGET" 2>/dev/null || true)

# ── Private Keys ──────────────────────────────────────────────────────────────
echo "[ 4/11] Private keys and certificates..."

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "CRITICAL" "$file" "$line" "Private Key" "PEM private key block found in file"
done < <(grep -rn $EXCLUDE \
  -e '-----BEGIN RSA PRIVATE KEY-----' \
  -e '-----BEGIN EC PRIVATE KEY-----' \
  -e '-----BEGIN OPENSSH PRIVATE KEY-----' \
  -e '-----BEGIN PRIVATE KEY-----' \
  -e '-----BEGIN PGP PRIVATE KEY BLOCK-----' \
  "$TARGET" 2>/dev/null || true)

# ── Source Control Tokens ─────────────────────────────────────────────────────
echo "[ 5/11] Source control tokens..."

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "HIGH" "$file" "$line" "GitHub Token" "ghp_/gho_/ghs_ token detected"
done < <(grep -rn $EXCLUDE -e 'gh[pos]_[A-Za-z0-9]\{36\}' "$TARGET" 2>/dev/null || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "HIGH" "$file" "$line" "GitLab Token" "glpat- token detected"
done < <(grep -rn $EXCLUDE -e 'glpat-[A-Za-z0-9_-]\{20\}' "$TARGET" 2>/dev/null || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "HIGH" "$file" "$line" "HashiCorp Vault Token" "hvs. token detected"
done < <(grep -rn $EXCLUDE -e 'hvs\.[A-Za-z0-9_-]\{90,\}' "$TARGET" 2>/dev/null || true)

# ── SaaS API Keys ─────────────────────────────────────────────────────────────
echo "[ 6/11] SaaS API keys..."

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "HIGH" "$file" "$line" "Slack Token" "xoxb-/xoxp- token detected"
done < <(grep -rn $EXCLUDE -e 'xox[bpa]-[0-9A-Za-z-]\{40,\}' "$TARGET" 2>/dev/null || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "HIGH" "$file" "$line" "Stripe Live Key" "sk_live_ key detected"
done < <(grep -rn $EXCLUDE -e 'sk_live_[0-9A-Za-z]\{24,\}' "$TARGET" 2>/dev/null || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "HIGH" "$file" "$line" "Databricks Token" "dapi token detected"
done < <(grep -rn $EXCLUDE -e 'dapi[A-Za-z0-9]\{32\}' "$TARGET" 2>/dev/null || true)

# ── Database DSNs ─────────────────────────────────────────────────────────────
echo "[ 7/11] Database connection strings..."

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "HIGH" "$file" "$line" "Database DSN with password" "Credentials embedded in connection string"
done < <(grep -rn $EXCLUDE \
  -e 'postgres://[^:]*:[^@]\{4,\}@' \
  -e 'mysql://[^:]*:[^@]\{4,\}@' \
  -e 'mongodb[+a-z]*://[^:]*:[^@]\{4,\}@' \
  -e 'redis://[^:]*:[^@]\{4,\}@' \
  "$TARGET" 2>/dev/null || true)

# ── IaC Hardcoded Passwords ───────────────────────────────────────────────────
echo "[ 8/11] IaC hardcoded passwords..."

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "MEDIUM" "$file" "$line" "Hardcoded password in IaC" "Literal value in password/secret field"
done < <(grep -rn \
  --include='*.tf' --include='*.hcl' \
  --exclude-dir='.git' --exclude-dir='.terraform' --exclude-dir='.terragrunt-cache' \
  -e 'password\s*=\s*"[^"$][^"]\{4,\}"' \
  -e 'secret\s*=\s*"[^"$][^"]\{4,\}"' \
  "$TARGET" 2>/dev/null || true)

# ── Kubernetes ────────────────────────────────────────────────────────────────
echo "[ 9/11] Kubernetes manifests..."

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "HIGH" "$file" "$line" "Kubernetes Secret with stringData" "Plaintext secrets in K8s manifest"
done < <(grep -rn --include='*.yaml' --include='*.yml' $EXCLUDE \
  -e 'stringData\s*:' "$TARGET" 2>/dev/null || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "MEDIUM" "$file" "$line" "Helm values with hardcoded secret" "Plaintext secret in Helm values file"
done < <(find "$TARGET" \( -name 'values.yaml' -o -name 'values-*.yaml' -o -name 'secrets.yaml' \) \
  -not -path '*/.git/*' \
  -exec grep -Hn \
    -e 'password\s*:\s*["'"'"'][^"'"'"']\{4,\}["'"'"']' \
    -e 'token\s*:\s*["'"'"'][^"'"'"']\{8,\}["'"'"']' \
    {} \; 2>/dev/null || true)

# ── Ansible ───────────────────────────────────────────────────────────────────
echo "[10/11] Ansible playbooks..."

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "MEDIUM" "$file" "$line" "Ansible plaintext credential" "ansible_password or ssh password in plaintext"
done < <(grep -rn --include='*.yaml' --include='*.yml' --include='*.ini' $EXCLUDE \
  -e 'ansible_password\s*:\s*["'"'"'][^"'"'"']\{4,\}["'"'"']' \
  -e 'ansible_ssh_pass\s*:\s*["'"'"'][^"'"'"']\{4,\}["'"'"']' \
  -e 'ansible_become_pass\s*:\s*["'"'"'][^"'"'"']\{4,\}["'"'"']' \
  "$TARGET" 2>/dev/null || true)

# ── Committed Sensitive Files ─────────────────────────────────────────────────
echo "[11/11] Committed sensitive files..."

while read -r file; do
  [[ -z "$file" ]] && continue
  add_finding "MEDIUM" "$file" "-" "Committed .tfvars file" "May contain real credential values"
done < <(find "$TARGET" \( -name '*.tfvars' -o -name 'terraform.tfvars' \) \
  -not -path '*/.git/*' -not -path '*/.terraform/*' 2>/dev/null || true)

while read -r file; do
  [[ -z "$file" ]] && continue
  add_finding "CRITICAL" "$file" "-" "Committed Terraform state file" "Contains all resource attribute values in plaintext"
done < <(find "$TARGET" \( -name '*.tfstate' -o -name '*.tfstate.backup' \) \
  -not -path '*/.git/*' 2>/dev/null || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  echo "$rest" | grep -qiE 'your_|replace|changeme|\$\{|\$\(|<YOUR|=example|=test|=sample|=fake' && continue
  add_finding "MEDIUM" "$file" "$line" "Secret in .env file" "Hardcoded value in environment file"
done < <(find "$TARGET" \( -name '.env' -o -name '*.env' -o -name '.env.*' \) \
  -not -path '*/.git/*' -not -path '*/node_modules/*' \
  -exec grep -Hn '=.\{6,\}' {} \; 2>/dev/null | grep -v 'NODE_ENV\|#\|URL=http' || true)

while IFS=: read -r file line rest; do
  [[ -z "$file" ]] && continue
  add_finding "LOW" "$file" "$line" "Variable missing sensitive=true" "Secret variable declared without sensitive = true"
done < <(grep -rn --include='*.tf' --exclude-dir='.git' --exclude-dir='.terraform' \
  -e 'variable\s*"[^"]*\(password\|secret\|key\|token\|credential\)[^"]*"' \
  "$TARGET" 2>/dev/null || true)

# ── Report ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD}   Scan Report${NC}"
echo -e "${BOLD}================================================${NC}"
echo "Scanned : ${TARGET}"
echo -e "Findings: ${BOLD}${FINDINGS}${NC} total — ${RED}${CRITICAL} CRITICAL${NC} · ${RED}${HIGH} HIGH${NC} · ${YELLOW}${MEDIUM} MEDIUM${NC} · ${BOLD}${LOW} LOW${NC}"
echo ""

if [[ $FINDINGS -gt 0 ]]; then
  echo -e "$REPORT"
fi

echo -e "${BOLD}================================================${NC}"

if [[ $CRITICAL -gt 0 ]] || [[ $HIGH -gt 0 ]]; then
  echo -e "${RED}${BOLD}FAILED — Rotate exposed credentials immediately and fix before merging.${NC}"
  exit 1
elif [[ $MEDIUM -gt 0 ]] || [[ $LOW -gt 0 ]]; then
  echo -e "${YELLOW}${BOLD}WARNING — Review findings before merging.${NC}"
  exit 0
else
  echo -e "${BOLD}PASSED — No hardcoded secrets detected.${NC}"
  exit 0
fi
