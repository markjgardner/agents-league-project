# Example App — Intentionally Vulnerable Demo

This directory contains a **deliberately insecure** application used to
demonstrate the RedTeam Agent's scanning capabilities. It is designed for
**local/CI demo use only** and should never be deployed to production.

## What triggers findings

| Scanner | Trigger | Expected severity |
|---------|---------|-------------------|
| secret-detection | `secrets.example` contains fake AWS keys and a generic password | critical / high |
| http-scan | `server.cjs` serves responses without security headers and exposes `/.env` | high / medium |

## Running locally

### Secret-detection scan only

No server needed — just point the agent at this directory:

```bash
# From the repo root
REDTEAM_REPO_ROOT=example npx tsx src/index.ts --no-issues --json
```

### HTTP scan (optional)

Start the intentionally insecure server:

```bash
cd example
node server.cjs &         # Starts on http://localhost:4200
```

Then run the agent with the example config:

```bash
# From the repo root
npx tsx src/index.ts --demo --no-issues --json --config example/redteam.example.json
```

Stop the server when done:

```bash
kill %1   # or: kill $(lsof -t -i:4200)
```

## Cleanup

All issues created during a demo run carry the label **`demo:redteam-example`**.

To close them manually:

```bash
gh issue list --label "demo:redteam-example" --state open --json number \
  | jq -r '.[].number' \
  | xargs -I{} gh issue close {} --reason "not planned" \
      --comment "Closed: demo issue cleanup"
```

Or trigger the cleanup job in the
[redteam-example workflow](../.github/workflows/redteam-example.yml)
with the `cleanup` input set to `true`.
