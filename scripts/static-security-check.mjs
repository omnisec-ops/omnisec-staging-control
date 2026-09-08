import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];

function requireText(source, text, label) {
  if (!source.includes(text)) failures.push(`missing:${label}`);
}

function forbid(source, expression, label) {
  if (expression.test(source)) failures.push(`forbidden:${label}`);
}

async function read(relativePath) {
  return readFile(path.join(ROOT, relativePath), "utf8");
}

async function listSourceFiles(directory = ROOT) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if ([".git", "node_modules"].includes(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await listSourceFiles(absolute));
    else if (entry.isFile()) files.push(absolute);
  }
  return files;
}

export async function scanControlRepository() {
  failures.length = 0;
  const workflowDirectory = path.join(ROOT, ".github", "workflows");
  const workflowFiles = (await readdir(workflowDirectory)).filter((name) => /\.ya?ml$/.test(name));
  const workflows = new Map();
  for (const name of workflowFiles) workflows.set(name, await read(path.join(".github", "workflows", name)));
  const allWorkflows = [...workflows.values()].join("\n");

  const sourceFiles = await listSourceFiles();
  const allSource = (await Promise.all(sourceFiles.map((file) => readFile(file, "utf8")))).join("\n");
  const executableFiles = sourceFiles.filter((file) => file.includes(`${path.sep}scripts${path.sep}`)
    && file.endsWith(".mjs")
    && path.basename(file) !== "static-security-check.mjs");
  const executableSource = (await Promise.all(executableFiles.map((file) => readFile(file, "utf8")))).join("\n");
  if (sourceFiles.some((file) => /(^|[\\/])\.env(?:\.|$)/.test(file))) failures.push("forbidden:environment-file");
  forbid(allSource, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, "private-key-material");
  forbid(allSource, /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/, "github-token-material");
  forbid(allSource, /\bAKIA[A-Z0-9]{16}\b/, "aws-key-material");
  forbid(allSource, /https?:\/\/[^\s/:@]+:[^\s/@]+@/, "credential-bearing-url");
  forbid(allSource, /\b\d{1,3}(?:\.\d{1,3}){3}\b/, "raw-ipv4");
  forbid(executableSource, /\b(?:ssh|scp|rsync|ansible-playbook|kubectl|terraform)\b/i, "script-remote-execution");
  forbid(executableSource, /["'`]docker["'`][\s\S]{0,120}["'`](?:build|compose|run|push)["'`]/i, "script-deployment-command");
  for (const match of executableSource.matchAll(/https?:\/\/[^\s"'`)]+/g)) {
    const value = match[0];
    if (!["https://api.github.com/", "https://github.com/", "https://in-toto.io/Statement/", "https://token.actions.githubusercontent.com"].some((prefix) => value.startsWith(prefix))) {
      failures.push("forbidden:script-unapproved-network-endpoint");
    }
  }

  forbid(allWorkflows, /runs-on:\s*(?:\[[^\]]*)?self-hosted/i, "self-hosted-runner");
  forbid(allWorkflows, /\b(?:ssh|scp|rsync|ansible-playbook|kubectl\s+apply|docker\s+(?:build|compose|run|push))\b/i, "deployment-command");
  forbid(allWorkflows, /\b(?:curl|wget|Invoke-WebRequest)\b/i, "unreviewed-network-client");
  forbid(allWorkflows, /\$\{\{\s*secrets\./, "repository-secret");
  forbid(allWorkflows, /certificate-(?:identity|oidc-issuer)-regexp/, "regex-certificate-identity");
  forbid(allWorkflows, /--insecure-ignore-(?:tlog|sct)|--check-claims(?:=|\s+)false/, "cosign-verification-bypass");
  forbid(allWorkflows, /COSIGN_PRIVATE_KEY|COSIGN_PASSWORD|SIGNING_KEY|\s--key(?:=|\s)/, "long-lived-signing-key");
  forbid(allWorkflows, /github\.triggering_actor/, "dispatcher-as-reviewer");

  for (const [name, source] of workflows) {
    for (const match of source.matchAll(/uses:\s*([^\s@]+)@([^\s#]+)/g)) {
      if (!/^[a-f0-9]{40}$/.test(match[2])) failures.push(`mutable-action:${name}:${match[1]}`);
    }
  }

  const authorization = workflows.get("staging-authorization.yml") ?? "";
  for (const text of [
    "workflow_dispatch:",
    "source_revision:",
    "source_state_hash:",
    "manifest_sha256:",
    "publish_workflow_sha:",
    "backend_image:",
    "frontend_image:",
    "permissions: {}",
    "github.repository == 'HKTeerawat/omnisec-staging-control'",
    "github.event_name == 'workflow_dispatch'",
    "github.ref == 'refs/heads/main'",
    "github.run_attempt == 1",
    "packages: read",
    "actions: read",
    "id-token: write",
    "name: staging",
    "deployment: false",
    "verify-candidate.mjs",
    "Reverify candidate after approval",
    "fetch-review-evidence.mjs",
    "--certificate-identity \"$EXPECTED_AUTHORIZATION_WORKFLOW_IDENTITY\"",
    "--certificate-oidc-issuer \"$EXPECTED_OIDC_ISSUER\"",
    "--certificate-github-workflow-repository \"$EXPECTED_CONTROL_REPOSITORY\"",
    "--certificate-github-workflow-ref refs/heads/main",
    "--certificate-github-workflow-trigger workflow_dispatch",
    "--certificate-github-workflow-sha \"$GITHUB_SHA\"",
    "retention-days: 1",
  ]) requireText(authorization, text, `authorization:${text}`);
  forbid(authorization, /^\s{2}(?:push|pull_request|schedule|workflow_call):/m, "authorization-non-manual-trigger");
  forbid(authorization, /traffic_percentage:/, "variable-traffic-input");
  if ((authorization.match(/id-token:\s*write/g) ?? []).length !== 1) failures.push("authorization:id-token-scope-invalid");
  if ((authorization.match(/environment:/g) ?? []).length !== 1) failures.push("authorization:environment-scope-invalid");

  const schema = JSON.parse(await read(path.join("schemas", "deployment-authorization.schema.json")));
  if (schema.additionalProperties !== false) failures.push("schema:open-root");
  if (schema.properties?.targetTrafficPercentage?.const !== 0) failures.push("schema:traffic-not-zero");
  if (schema.properties?.controlRepository?.const !== "HKTeerawat/omnisec-staging-control") failures.push("schema:control-repository-not-exact");
  if (schema.properties?.authorizationWorkflowIdentity?.const !== "https://github.com/HKTeerawat/omnisec-staging-control/.github/workflows/staging-authorization.yml@refs/heads/main") failures.push("schema:workflow-identity-not-exact");

  const policy = JSON.parse(await read(path.join("policies", "queue-v2-staging-policy.json")));
  if (policy.target?.name !== "staging-target-unconfigured") failures.push("policy:target-claims-readiness");
  for (const [name, provider] of Object.entries(policy.providers ?? {})) {
    if (provider?.configured !== false || provider?.name !== "unconfigured") failures.push(`policy:${name}-claims-readiness`);
  }

  const verifier = await read(path.join("scripts", "verify-authorization.mjs"));
  for (const text of ["validateAuthorizationRecord", "validateCandidateAttestations", "consumeAuthorizationId", "authorizationCosignArgs"]) {
    requireText(verifier, text, `verifier:${text}`);
  }

  return { failures: [...failures], workflows: workflowFiles.length };
}

async function runCli() {
  const result = await scanControlRepository();
  if (result.failures.length > 0) {
    process.stderr.write(`${JSON.stringify({ status: "failed", failures: result.failures })}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`${JSON.stringify({ status: "passed", workflows: result.workflows })}\n`);
}

if (path.resolve(process.argv[1] ?? "") === path.resolve(fileURLToPath(import.meta.url))) {
  runCli().catch(() => {
    process.stderr.write(`${JSON.stringify({ status: "failed", failures: ["diagnostic_unavailable"] })}\n`);
    process.exitCode = 1;
  });
}
