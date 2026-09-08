# Staging authorization trust contract

## Boundary

The public control repository may verify an existing private GHCR candidate and issue a signed authorization. It must never build application images, contact the staging host, deploy, change traffic, run migrations, or hold durable credentials.

The checked-in workflow is manual-only on `main`, attempt 1 only, and GitHub-hosted only. Its signing job is protected by the `staging` environment with required reviewer, prevent-self-review, no administrator bypass, selected branch `main`, and `deployment: false`.

## Candidate evidence

Backend and frontend are separate immutable digest references. Each must have a Cosign signature and source attestation issued by:

- issuer `https://token.actions.githubusercontent.com`
- repository `HKTeerawat/omnisec-security-platform`
- workflow `staging-publish`
- identity `https://github.com/HKTeerawat/omnisec-security-platform/.github/workflows/staging-publish.yml@refs/heads/main`
- ref `refs/heads/main`
- event `workflow_dispatch`
- the exact full publish workflow SHA supplied to the authorization request and matched against the certificate and attestation

The attestation must bind the exact image digest to the full source revision, clean source state hash, canonical manifest hash, role, and fixed predicate type. Both image attestations must agree on all shared values. Inputs alone are never trust evidence.

Because the application repository and packages are private, the package settings must explicitly grant this control repository Actions read access. The workflow receives only its ephemeral `GITHUB_TOKEN` with `packages: read`. Missing access is a hard failure; package visibility must not be broadened as a workaround.

## Independent approval and signed record

The protected job fetches its own GitHub workflow-run approval history after the environment gate. It requires exactly one approved `staging` review and compares the immutable numeric reviewer and initiator IDs. A missing, ambiguous, malformed, or self review blocks signing.

The public artifact deliberately omits reviewer login and ID. It records only that the exact trusted workflow verified an independent reviewer, plus the public workflow run ID. The authorization fixes staging traffic at 0%, expires within two hours, and cannot be produced by a rerun.

## Host verification

The host verifier requires locally pinned expectations for:

- the currently trusted control-workflow SHA
- the authoritative current application `main` source SHA
- both intended image digest references

These values must come from the host control plane, not from the downloaded record, environment variables supplied by an untrusted client, tags, or build arguments. The host must authenticate to private GHCR out of band and must not place credentials in this repository or logs.

Before a deployment adapter can run, the host verifier:

1. validates the closed authorization schema, exact identities, 0% traffic, timestamps, and pinned expectations;
2. verifies the authorization bundle against the exact control workflow certificate claims;
3. re-verifies both image signatures and attestations against the exact application publish workflow claims;
4. validates the signed attestation payloads against the authorization; and
5. atomically records the authorization ID in a root-owned, persistent replay ledger.

A consumed authorization can never be reused. If verification succeeds but a later deployment action fails, a new approval and authorization are required. A missing or locked ledger, malformed evidence, unavailable registry, failed transparency check, expired record, or mismatch is `blocked`.

## Readiness

All target and provider adapters remain `unconfigured` in source until separate evidence confirms a dedicated Linux host, private ingress, staging-only persistent data, observability, rollback authority, and the fail-closed adapter implementation. This repository issues authorization only; it does not make staging deployable by itself.
