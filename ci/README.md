# CI Integration

Two ways to integrate the secrets scanner into your pipeline.

---

## Option 1 — Shell Script (recommended for CI)

Fast, zero-dependency, no API key needed. Runs the same grep patterns as the Claude skill.

### Add to your project

```bash
# Download the script into your repo
curl -fsSL https://raw.githubusercontent.com/goku-70/secrets-scanner-skill/main/ci/scan.sh \
  -o scripts/scan.sh
chmod +x scripts/scan.sh
```

### Run manually
```bash
# Scan entire repo
./scripts/scan.sh

# Scan a specific path
./scripts/scan.sh ./terraform
./scripts/scan.sh ./k8s
```

### Exit codes
| Code | Meaning |
|------|---------|
| `0` | Clean or only LOW/MEDIUM findings |
| `1` | CRITICAL or HIGH findings — fails the build |

---

## Option 2 — Claude Code (manual / on-demand)

Full intelligent scan with false-positive filtering. Requires `ANTHROPIC_API_KEY`.

```bash
# Install the skill once
claude plugin marketplace add https://raw.githubusercontent.com/goku-70/secrets-scanner-skill/main/marketplace.json
claude plugin install secrets-scanner

# Run in CI (non-interactive)
claude -p "/secrets-scanner:secrets-scanner ." --output-format text
```

---

## GitHub Actions Setup

### Step 1 — Copy the workflow file into your repo

```bash
mkdir -p .github/workflows
curl -fsSL https://raw.githubusercontent.com/goku-70/secrets-scanner-skill/main/ci/github-actions-workflow.yml \
  -o .github/workflows/secrets-scan.yml
```

### Step 2 — (Optional) Add ANTHROPIC_API_KEY for Claude mode

In your GitHub repo: **Settings → Secrets and variables → Actions → New repository secret**

```
Name:  ANTHROPIC_API_KEY
Value: your-anthropic-api-key
```

Only needed for the `claude` scan mode. Shell mode works without it.

### Step 3 — Commit and push

```bash
git add .github/workflows/secrets-scan.yml
git commit -m "Add secrets scanner to CI pipeline"
git push
```

---

## How the Workflow Triggers

| Trigger | Mode | What runs |
|---------|------|-----------|
| PR opened / updated | Automatic | Shell scan — fast, blocks merge on CRITICAL/HIGH |
| Push to `main` | Automatic | Shell scan — post-merge verification |
| Manual (`workflow_dispatch`) | Manual | Choose `shell` or `claude` mode, optional path |

### Manual trigger from GitHub UI

1. Go to your repo → **Actions** tab
2. Select **Secrets Scanner** workflow
3. Click **Run workflow**
4. Set path (e.g. `./terraform`) and mode (`shell` or `claude`)
5. Click **Run workflow**

---

## What Happens on a PR

1. Developer opens a PR
2. Secrets Scanner runs automatically
3. Results are posted as a PR comment
4. If CRITICAL or HIGH findings exist → build fails → merge is blocked
5. Developer fixes secrets, pushes again → scan re-runs

```
PR opened
    │
    ▼
Secrets scan runs (shell mode)
    │
    ├── No CRITICAL/HIGH findings → ✅ Check passes → PR can merge
    │
    └── CRITICAL/HIGH found → ❌ Check fails → PR blocked
                                    │
                                    ▼
                              Comment posted on PR
                              with findings + remediation
```

---

## Blocking Merge on Failed Scan

To enforce the scan as a required check before merging:

1. Go to **Settings → Branches → Branch protection rules**
2. Edit the rule for `main`
3. Under **Require status checks to pass before merging**
4. Search for and add: `Secrets Scan (Shell)`
5. Save

Now no PR can merge to `main` if secrets are detected.
