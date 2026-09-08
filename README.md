# OmniSec Staging Deployment Control Plane

This directory is a source-only draft for a future public repository. It must not be published or used until repository settings and private-package access have been independently verified.

## Security Architecture
- **No application source, durable credentials, or host endpoints**: only public trust policy and bounded metadata belong here.
- **Independent review gate**: the signing job uses the protected `staging` environment with required review, prevent-self-review, main-only policy, and deployment recording disabled.
- **Exact candidate trust**: backend and frontend digest references must independently pass exact Sigstore issuer, repository, workflow, ref, event, workflow-SHA, source-revision, clean-state, and manifest-hash checks before and after approval.
- **Keyless authorization**: the approved 0%-traffic record is valid for at most two hours and is signed with GitHub Actions OIDC. No long-lived signing key is permitted.
- **Pull-based host verification**: the staging host re-verifies the authorization and both image attestations against host-pinned expectations, then atomically consumes the authorization ID before any separately implemented deployment action.
- **Fail-closed readiness**: target and provider adapters remain `unconfigured` until separate control-plane evidence proves they exist.

## Repository Contents
- `.github/workflows/`: CI test suites and GitHub-hosted authorization workflow.
- `schemas/`: JSON Schemas for deployment authorizations.
- `policies/`: Symbolic fail-closed staging contract policies.
- `scripts/`: Generator and pull-based verification scripts.
- `test/`: Node-only fail-closed policy tests; no network, Docker, or deployment is used.
- `docs/`: Independent reviewer instructions and repository setup guides.

See `docs/TRUST_CONTRACT.md` before configuring the repository or staging host.
