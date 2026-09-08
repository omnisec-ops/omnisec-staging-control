import { randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

const FULL_SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const RUN_ID = /^[1-9][0-9]{0,19}$/;
const USER_ID = /^[1-9][0-9]{0,19}$/;
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_JSON_BYTES = 1024 * 1024;
const AUTHORIZATION_LIFETIME_MS = 2 * 60 * 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;

const CANDIDATE_FIELDS = [
  "backendImage",
  "frontendImage",
  "manifestSha256",
  "publishWorkflowSha",
  "sourceRevision",
  "sourceStateHash",
];
const VERIFIED_CANDIDATE_FIELDS = ["status", ...CANDIDATE_FIELDS];
const REVIEW_PROOF_FIELDS = [
  "approved",
  "environment",
  "independentReviewerVerified",
  "provider",
  "schemaVersion",
  "workflowRunId",
];
const REVIEW_GATE_FIELDS = [
  "environment",
  "independentReviewerVerified",
  "provider",
  "workflowRunId",
];
const RECORD_FIELDS = [
  "authorizationEvent",
  "authorizationId",
  "authorizationRunAttempt",
  "authorizationRunId",
  "authorizationWorkflowIdentity",
  "authorizationWorkflowRef",
  "authorizationWorkflowSha",
  "authorizedAt",
  "backendImage",
  "controlRepository",
  "expiresAt",
  "frontendImage",
  "manifestSha256",
  "publishWorkflowSha",
  "reviewGate",
  "schemaVersion",
  "sourceRef",
  "sourceRepository",
  "sourceRevision",
  "sourceStateHash",
  "targetEnvironment",
  "targetTrafficPercentage",
];
const PREDICATE_FIELDS = [
  "clean",
  "eventName",
  "imageRole",
  "manifestSha256",
  "repository",
  "schemaVersion",
  "sourceRef",
  "sourceRevision",
  "sourceStateHash",
  "workflowIdentity",
  "workflowRef",
  "workflowSha",
];
const STATEMENT_TYPES = new Set([
  "https://in-toto.io/Statement/v1",
  "https://in-toto.io/Statement/v0.1",
]);

export const CONTROL_CONTRACT = Object.freeze({
  schemaVersion: 1,
  controlRepository: "HKTeerawat/omnisec-staging-control",
  authorizationWorkflowName: "staging-authorization",
  authorizationWorkflowRef: "refs/heads/main",
  authorizationWorkflowIdentity: "https://github.com/HKTeerawat/omnisec-staging-control/.github/workflows/staging-authorization.yml@refs/heads/main",
  authorizationEvent: "workflow_dispatch",
  sourceRepository: "HKTeerawat/omnisec-security-platform",
  sourceRef: "refs/heads/main",
  publishWorkflowName: "staging-publish",
  publishWorkflowRef: "refs/heads/main",
  publishWorkflowIdentity: "https://github.com/HKTeerawat/omnisec-security-platform/.github/workflows/staging-publish.yml@refs/heads/main",
  publishEvent: "workflow_dispatch",
  issuer: "https://token.actions.githubusercontent.com",
  predicateType: "https://github.com/HKTeerawat/omnisec-security-platform/attestations/source/v1",
  environment: "staging",
  trafficPercentage: 0,
  backendRepository: "ghcr.io/hkteerawat/omnisec-backend",
  frontendRepository: "ghcr.io/hkteerawat/omnisec-frontend",
  authorizationLifetimeMs: AUTHORIZATION_LIFETIME_MS,
});

export class AuthorizationPolicyError extends Error {
  constructor(code) {
    super(code);
    this.name = "AuthorizationPolicyError";
    this.code = code;
  }
}

function fail(code) {
  throw new AuthorizationPolicyError(code);
}

function assertExactFields(value, expected, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(code);
}

function parseBoundedJson(raw, code) {
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > MAX_JSON_BYTES) fail(code);
  try {
    return JSON.parse(raw);
  } catch {
    fail(code);
  }
}

function assertFullSha(value, code) {
  if (!FULL_SHA.test(value ?? "")) fail(code);
}

function assertSha256(value, code) {
  if (!SHA256.test(value ?? "")) fail(code);
}

function assertImage(value, role) {
  const repository = CONTROL_CONTRACT[`${role}Repository`];
  const match = new RegExp(`^${repository.replaceAll(".", "\\.")}@sha256:([a-f0-9]{64})$`).exec(value ?? "");
  if (!match) fail(`${role}_image_invalid`);
  return { repository, digest: match[1] };
}

function assertIsoTimestamp(value, code) {
  if (typeof value !== "string") fail(code);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) fail(code);
  return timestamp;
}

export function validateCandidateInput(value) {
  assertExactFields(value, CANDIDATE_FIELDS, "candidate_fields_invalid");
  assertFullSha(value.sourceRevision, "source_revision_invalid");
  assertSha256(value.sourceStateHash, "source_state_hash_invalid");
  assertSha256(value.manifestSha256, "manifest_hash_invalid");
  assertFullSha(value.publishWorkflowSha, "publish_workflow_sha_invalid");
  assertImage(value.backendImage, "backend");
  assertImage(value.frontendImage, "frontend");
  return Object.freeze({ ...value });
}

function expectedPredicate(candidate, role) {
  return {
    schemaVersion: 1,
    repository: CONTROL_CONTRACT.sourceRepository,
    workflowIdentity: CONTROL_CONTRACT.publishWorkflowIdentity,
    workflowRef: CONTROL_CONTRACT.publishWorkflowRef,
    eventName: CONTROL_CONTRACT.publishEvent,
    workflowSha: candidate.publishWorkflowSha,
    sourceRevision: candidate.sourceRevision,
    sourceRef: CONTROL_CONTRACT.sourceRef,
    sourceStateHash: candidate.sourceStateHash,
    manifestSha256: candidate.manifestSha256,
    imageRole: role,
    clean: true,
  };
}

function decodeStatements(raw) {
  const parsed = parseBoundedJson(raw, "attestation_output_invalid");
  const records = Array.isArray(parsed) ? parsed : [parsed];
  if (records.length === 0 || records.length > 16) fail("attestation_output_invalid");
  return records.map((record) => {
    if (record?._type && record?.predicate) return record;
    if (typeof record?.payload !== "string" || record.payload.length > MAX_JSON_BYTES) fail("attestation_payload_invalid");
    let decoded;
    try {
      decoded = Buffer.from(record.payload, "base64").toString("utf8");
    } catch {
      fail("attestation_payload_invalid");
    }
    return parseBoundedJson(decoded, "attestation_payload_invalid");
  });
}

function validateRoleAttestations(candidate, role, raw) {
  const image = assertImage(candidate[`${role}Image`], role);
  const expected = expectedPredicate(candidate, role);
  const statements = decodeStatements(raw);
  for (const statement of statements) {
    if (!STATEMENT_TYPES.has(statement?._type) || statement.predicateType !== CONTROL_CONTRACT.predicateType) fail(`${role}_attestation_type_invalid`);
    if (!Array.isArray(statement.subject) || statement.subject.length !== 1) fail(`${role}_attestation_subject_invalid`);
    const subject = statement.subject[0];
    if (subject?.name !== image.repository || subject?.digest?.sha256 !== image.digest) fail(`${role}_attestation_subject_invalid`);
    assertExactFields(statement.predicate, PREDICATE_FIELDS, `${role}_attestation_predicate_invalid`);
    if (PREDICATE_FIELDS.some((field) => statement.predicate[field] !== expected[field])) fail(`${role}_attestation_predicate_invalid`);
  }
}

export function validateCandidateAttestations({ candidate: input, backendOutput, frontendOutput }) {
  const candidate = validateCandidateInput(input);
  validateRoleAttestations(candidate, "backend", backendOutput);
  validateRoleAttestations(candidate, "frontend", frontendOutput);
  return Object.freeze({ status: "verified", ...candidate });
}

export function validateReviewHistory({ raw, initiatorLogin, initiatorId, workflowRunId }) {
  if (!LOGIN.test(initiatorLogin ?? "") || !USER_ID.test(String(initiatorId ?? "")) || !RUN_ID.test(String(workflowRunId ?? ""))) {
    fail("review_context_invalid");
  }
  const history = parseBoundedJson(raw, "review_history_invalid");
  if (!Array.isArray(history) || history.length > 32) fail("review_history_invalid");
  const approvals = history.filter((entry) => entry?.state === "approved"
    && Array.isArray(entry.environments)
    && entry.environments.some((environment) => environment?.name === CONTROL_CONTRACT.environment));
  if (approvals.length !== 1) fail("independent_review_missing_or_ambiguous");
  const reviewer = approvals[0]?.user;
  if (!LOGIN.test(reviewer?.login ?? "") || !USER_ID.test(String(reviewer?.id ?? ""))) fail("reviewer_identity_invalid");
  if (String(reviewer.id) === String(initiatorId) || reviewer.login.toLowerCase() === initiatorLogin.toLowerCase()) fail("self_review_rejected");
  return Object.freeze({
    schemaVersion: 1,
    provider: "github-actions-environment",
    environment: CONTROL_CONTRACT.environment,
    workflowRunId: String(workflowRunId),
    approved: true,
    independentReviewerVerified: true,
  });
}

function validateReviewProof(value) {
  assertExactFields(value, REVIEW_PROOF_FIELDS, "review_proof_fields_invalid");
  if (value.schemaVersion !== 1
    || value.provider !== "github-actions-environment"
    || value.environment !== CONTROL_CONTRACT.environment
    || value.approved !== true
    || value.independentReviewerVerified !== true
    || !RUN_ID.test(value.workflowRunId ?? "")) fail("review_proof_invalid");
  return value;
}

export function buildAuthorizationRecord({ candidate: verifiedInput, reviewProof: proofInput, authorizationWorkflowSha, authorizationRunId, authorizationRunAttempt, now = new Date(), authorizationId = randomUUID() }) {
  assertExactFields(verifiedInput, VERIFIED_CANDIDATE_FIELDS, "verified_candidate_fields_invalid");
  if (verifiedInput.status !== "verified") fail("candidate_not_verified");
  const candidate = validateCandidateInput(Object.fromEntries(CANDIDATE_FIELDS.map((field) => [field, verifiedInput[field]])));
  const reviewProof = validateReviewProof(proofInput);
  assertFullSha(authorizationWorkflowSha, "authorization_workflow_sha_invalid");
  if (!RUN_ID.test(String(authorizationRunId ?? "")) || String(authorizationRunAttempt) !== "1") fail("authorization_run_invalid");
  if (reviewProof.workflowRunId !== String(authorizationRunId)) fail("review_run_mismatch");
  if (!UUID_V4.test(authorizationId)) fail("authorization_id_invalid");
  const authorizedAt = new Date(now);
  if (!Number.isFinite(authorizedAt.getTime())) fail("authorization_time_invalid");
  const expiresAt = new Date(authorizedAt.getTime() + AUTHORIZATION_LIFETIME_MS);
  return Object.freeze({
    schemaVersion: 1,
    authorizationId,
    sourceRepository: CONTROL_CONTRACT.sourceRepository,
    sourceRevision: candidate.sourceRevision,
    sourceRef: CONTROL_CONTRACT.sourceRef,
    sourceStateHash: candidate.sourceStateHash,
    manifestSha256: candidate.manifestSha256,
    backendImage: candidate.backendImage,
    frontendImage: candidate.frontendImage,
    publishWorkflowSha: candidate.publishWorkflowSha,
    targetEnvironment: CONTROL_CONTRACT.environment,
    targetTrafficPercentage: CONTROL_CONTRACT.trafficPercentage,
    reviewGate: {
      provider: reviewProof.provider,
      environment: reviewProof.environment,
      workflowRunId: reviewProof.workflowRunId,
      independentReviewerVerified: true,
    },
    authorizedAt: authorizedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    controlRepository: CONTROL_CONTRACT.controlRepository,
    authorizationWorkflowIdentity: CONTROL_CONTRACT.authorizationWorkflowIdentity,
    authorizationWorkflowRef: CONTROL_CONTRACT.authorizationWorkflowRef,
    authorizationWorkflowSha,
    authorizationEvent: CONTROL_CONTRACT.authorizationEvent,
    authorizationRunId: String(authorizationRunId),
    authorizationRunAttempt: 1,
  });
}

export function validateAuthorizationRecord(record, expected, now = new Date()) {
  assertExactFields(record, RECORD_FIELDS, "authorization_fields_invalid");
  if (record.schemaVersion !== 1 || !UUID_V4.test(record.authorizationId ?? "")) fail("authorization_identity_invalid");
  if (record.sourceRepository !== CONTROL_CONTRACT.sourceRepository || record.sourceRef !== CONTROL_CONTRACT.sourceRef) fail("source_identity_invalid");
  assertFullSha(record.sourceRevision, "source_revision_invalid");
  assertSha256(record.sourceStateHash, "source_state_hash_invalid");
  assertSha256(record.manifestSha256, "manifest_hash_invalid");
  assertFullSha(record.publishWorkflowSha, "publish_workflow_sha_invalid");
  assertImage(record.backendImage, "backend");
  assertImage(record.frontendImage, "frontend");
  if (record.targetEnvironment !== CONTROL_CONTRACT.environment || record.targetTrafficPercentage !== 0) fail("deployment_target_invalid");
  assertExactFields(record.reviewGate, REVIEW_GATE_FIELDS, "review_gate_fields_invalid");
  if (record.reviewGate.provider !== "github-actions-environment"
    || record.reviewGate.environment !== CONTROL_CONTRACT.environment
    || record.reviewGate.independentReviewerVerified !== true
    || record.reviewGate.workflowRunId !== record.authorizationRunId) fail("review_gate_invalid");
  if (record.controlRepository !== CONTROL_CONTRACT.controlRepository
    || record.authorizationWorkflowIdentity !== CONTROL_CONTRACT.authorizationWorkflowIdentity
    || record.authorizationWorkflowRef !== CONTROL_CONTRACT.authorizationWorkflowRef
    || record.authorizationEvent !== CONTROL_CONTRACT.authorizationEvent) fail("authorization_workflow_identity_invalid");
  assertFullSha(record.authorizationWorkflowSha, "authorization_workflow_sha_invalid");
  if (!RUN_ID.test(record.authorizationRunId ?? "") || record.authorizationRunAttempt !== 1) fail("authorization_run_invalid");
  const authorizedAt = assertIsoTimestamp(record.authorizedAt, "authorization_time_invalid");
  const expiresAt = assertIsoTimestamp(record.expiresAt, "authorization_time_invalid");
  const current = new Date(now).getTime();
  if (!Number.isFinite(current) || expiresAt <= authorizedAt || expiresAt - authorizedAt > AUTHORIZATION_LIFETIME_MS) fail("authorization_lifetime_invalid");
  if (current < authorizedAt - CLOCK_SKEW_MS || current >= expiresAt) fail("authorization_not_current");
  const requiredExpected = ["authorizationWorkflowSha", "backendImage", "frontendImage", "sourceRevision"];
  assertExactFields(expected, requiredExpected, "trusted_expectations_invalid");
  if (record.authorizationWorkflowSha !== expected.authorizationWorkflowSha
    || record.sourceRevision !== expected.sourceRevision
    || record.backendImage !== expected.backendImage
    || record.frontendImage !== expected.frontendImage) fail("trusted_expectations_mismatch");
  return Object.freeze({ ...record, reviewGate: Object.freeze({ ...record.reviewGate }) });
}

function commonCertificateArgs({ identity, repository, workflowName, workflowRef, workflowSha, eventName }) {
  return [
    "--certificate-identity", identity,
    "--certificate-oidc-issuer", CONTROL_CONTRACT.issuer,
    "--certificate-github-workflow-name", workflowName,
    "--certificate-github-workflow-repository", repository,
    "--certificate-github-workflow-ref", workflowRef,
    "--certificate-github-workflow-trigger", eventName,
    "--certificate-github-workflow-sha", workflowSha,
    "--check-claims=true",
  ];
}

export function candidateCosignCommands(candidateInput) {
  const candidate = validateCandidateInput(candidateInput);
  const certificate = commonCertificateArgs({
    identity: CONTROL_CONTRACT.publishWorkflowIdentity,
    repository: CONTROL_CONTRACT.sourceRepository,
    workflowName: CONTROL_CONTRACT.publishWorkflowName,
    workflowRef: CONTROL_CONTRACT.publishWorkflowRef,
    workflowSha: candidate.publishWorkflowSha,
    eventName: CONTROL_CONTRACT.publishEvent,
  });
  return Object.freeze({
    backendSignature: ["verify", ...certificate, candidate.backendImage],
    frontendSignature: ["verify", ...certificate, candidate.frontendImage],
    backendAttestation: ["verify-attestation", ...certificate, "--type", CONTROL_CONTRACT.predicateType, "--output", "json", candidate.backendImage],
    frontendAttestation: ["verify-attestation", ...certificate, "--type", CONTROL_CONTRACT.predicateType, "--output", "json", candidate.frontendImage],
  });
}

export function authorizationCosignArgs(record, bundlePath) {
  if (typeof bundlePath !== "string" || bundlePath.length === 0) fail("bundle_path_invalid");
  return [
    "verify-blob",
    "--bundle", bundlePath,
    ...commonCertificateArgs({
      identity: CONTROL_CONTRACT.authorizationWorkflowIdentity,
      repository: CONTROL_CONTRACT.controlRepository,
      workflowName: CONTROL_CONTRACT.authorizationWorkflowName,
      workflowRef: CONTROL_CONTRACT.authorizationWorkflowRef,
      workflowSha: record.authorizationWorkflowSha,
      eventName: CONTROL_CONTRACT.authorizationEvent,
    }),
  ];
}

function validateLedger(value) {
  assertExactFields(value, ["consumedAuthorizationIds", "schemaVersion"], "replay_ledger_invalid");
  if (value.schemaVersion !== 1 || !Array.isArray(value.consumedAuthorizationIds) || value.consumedAuthorizationIds.length > 10000) fail("replay_ledger_invalid");
  if (value.consumedAuthorizationIds.some((id) => !UUID_V4.test(id))) fail("replay_ledger_invalid");
  return value;
}

export async function consumeAuthorizationId(ledgerPath, authorizationId) {
  if (typeof ledgerPath !== "string" || ledgerPath.length === 0 || !UUID_V4.test(authorizationId ?? "")) fail("replay_input_invalid");
  const parent = path.dirname(ledgerPath);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const parentStat = await lstat(parent);
  if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) fail("replay_ledger_directory_invalid");
  if (process.platform !== "win32") {
    if ((parentStat.mode & 0o077) !== 0) fail("replay_ledger_directory_permissions_invalid");
    if (typeof process.getuid === "function" && parentStat.uid !== process.getuid()) fail("replay_ledger_directory_owner_invalid");
  }
  const lockPath = `${ledgerPath}.lock`;
  try {
    await mkdir(lockPath, { mode: 0o700 });
  } catch {
    fail("replay_ledger_locked");
  }
  let temporaryPath;
  try {
    let ledger = { schemaVersion: 1, consumedAuthorizationIds: [] };
    try {
      const stat = await lstat(ledgerPath);
      if (stat.isSymbolicLink() || !stat.isFile()) fail("replay_ledger_invalid");
      if (process.platform !== "win32") {
        if ((stat.mode & 0o077) !== 0) fail("replay_ledger_permissions_invalid");
        if (typeof process.getuid === "function" && stat.uid !== process.getuid()) fail("replay_ledger_owner_invalid");
      }
      ledger = validateLedger(parseBoundedJson(await readFile(ledgerPath, "utf8"), "replay_ledger_invalid"));
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    if (ledger.consumedAuthorizationIds.includes(authorizationId)) fail("authorization_replayed");
    const next = { schemaVersion: 1, consumedAuthorizationIds: [...ledger.consumedAuthorizationIds, authorizationId] };
    temporaryPath = `${ledgerPath}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(next)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporaryPath, ledgerPath);
  } finally {
    if (temporaryPath) await rm(temporaryPath, { force: true });
    await rm(lockPath, { recursive: true, force: true });
  }
}

export function safeErrorCode(error) {
  return error instanceof AuthorizationPolicyError ? error.code : "diagnostic_unavailable";
}
