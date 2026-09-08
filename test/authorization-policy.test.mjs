import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  AuthorizationPolicyError,
  CONTROL_CONTRACT,
  authorizationCosignArgs,
  buildAuthorizationRecord,
  candidateCosignCommands,
  consumeAuthorizationId,
  safeErrorCode,
  validateAuthorizationRecord,
  validateCandidateAttestations,
  validateReviewHistory,
} from "../scripts/authorization-policy.mjs";

const SOURCE_SHA = "a".repeat(40);
const STATE_HASH = "b".repeat(64);
const MANIFEST_HASH = "c".repeat(64);
const PUBLISH_WORKFLOW_SHA = "d".repeat(40);
const AUTHORIZATION_WORKFLOW_SHA = "e".repeat(40);
const BACKEND_IMAGE = `${CONTROL_CONTRACT.backendRepository}@sha256:${"f".repeat(64)}`;
const FRONTEND_IMAGE = `${CONTROL_CONTRACT.frontendRepository}@sha256:${"1".repeat(64)}`;
const NOW = new Date("2026-09-08T00:00:00.000Z");
const AUTHORIZATION_ID = "12345678-1234-4abc-8abc-1234567890ab";

function candidate() {
  return {
    sourceRevision: SOURCE_SHA,
    sourceStateHash: STATE_HASH,
    manifestSha256: MANIFEST_HASH,
    publishWorkflowSha: PUBLISH_WORKFLOW_SHA,
    backendImage: BACKEND_IMAGE,
    frontendImage: FRONTEND_IMAGE,
  };
}

function predicate(role) {
  return {
    schemaVersion: 1,
    repository: CONTROL_CONTRACT.sourceRepository,
    workflowIdentity: CONTROL_CONTRACT.publishWorkflowIdentity,
    workflowRef: CONTROL_CONTRACT.publishWorkflowRef,
    eventName: CONTROL_CONTRACT.publishEvent,
    workflowSha: PUBLISH_WORKFLOW_SHA,
    sourceRevision: SOURCE_SHA,
    sourceRef: CONTROL_CONTRACT.sourceRef,
    sourceStateHash: STATE_HASH,
    manifestSha256: MANIFEST_HASH,
    imageRole: role,
    clean: true,
  };
}

function attestation(role, mutate = (statement) => statement) {
  const image = role === "backend" ? BACKEND_IMAGE : FRONTEND_IMAGE;
  const [name, digest] = image.split("@sha256:");
  const statement = mutate({
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name, digest: { sha256: digest } }],
    predicateType: CONTROL_CONTRACT.predicateType,
    predicate: predicate(role),
  });
  return JSON.stringify([{ payload: Buffer.from(JSON.stringify(statement)).toString("base64") }]);
}

function verifiedCandidate() {
  return validateCandidateAttestations({
    candidate: candidate(),
    backendOutput: attestation("backend"),
    frontendOutput: attestation("frontend"),
  });
}

function reviewProof() {
  return validateReviewHistory({
    initiatorLogin: "initiator",
    initiatorId: "100",
    workflowRunId: "123",
    raw: JSON.stringify([{
      state: "approved",
      environments: [{ name: "staging" }],
      user: { login: "reviewer", id: 200 },
    }]),
  });
}

function record() {
  return buildAuthorizationRecord({
    candidate: verifiedCandidate(),
    reviewProof: reviewProof(),
    authorizationWorkflowSha: AUTHORIZATION_WORKFLOW_SHA,
    authorizationRunId: "123",
    authorizationRunAttempt: "1",
    now: NOW,
    authorizationId: AUTHORIZATION_ID,
  });
}

function expected() {
  return {
    authorizationWorkflowSha: AUTHORIZATION_WORKFLOW_SHA,
    sourceRevision: SOURCE_SHA,
    backendImage: BACKEND_IMAGE,
    frontendImage: FRONTEND_IMAGE,
  };
}

function assertPolicyCode(fn, code) {
  assert.throws(fn, (error) => error instanceof AuthorizationPolicyError && error.code === code);
}

test("accepts only the exact signed backend/frontend candidate pair", () => {
  assert.deepEqual(verifiedCandidate(), { status: "verified", ...candidate() });
  assertPolicyCode(() => validateCandidateAttestations({
    candidate: candidate(),
    backendOutput: attestation("backend", (value) => ({ ...value, predicate: { ...value.predicate, clean: false } })),
    frontendOutput: attestation("frontend"),
  }), "backend_attestation_predicate_invalid");
  assertPolicyCode(() => validateCandidateAttestations({
    candidate: candidate(),
    backendOutput: attestation("backend"),
    frontendOutput: attestation("frontend", (value) => ({ ...value, subject: [{ ...value.subject[0], digest: { sha256: "2".repeat(64) } }] })),
  }), "frontend_attestation_subject_invalid");
});

test("requires exactly one approved reviewer distinct from the initiator without publishing identity", () => {
  assert.deepEqual(reviewProof(), {
    schemaVersion: 1,
    provider: "github-actions-environment",
    environment: "staging",
    workflowRunId: "123",
    approved: true,
    independentReviewerVerified: true,
  });
  assertPolicyCode(() => validateReviewHistory({
    initiatorLogin: "same-user",
    initiatorId: "100",
    workflowRunId: "123",
    raw: JSON.stringify([{ state: "approved", environments: [{ name: "staging" }], user: { login: "same-user", id: 100 } }]),
  }), "self_review_rejected");
  assertPolicyCode(() => validateReviewHistory({ initiatorLogin: "owner", initiatorId: "100", workflowRunId: "123", raw: "{}" }), "review_history_invalid");
  assertPolicyCode(() => validateReviewHistory({ initiatorLogin: "owner", initiatorId: "100", workflowRunId: "123", raw: "[]" }), "independent_review_missing_or_ambiguous");
});

test("authorization is exact, zero-traffic, time-bounded and expectation-bound", () => {
  const value = record();
  const result = validateAuthorizationRecord(value, expected(), new Date(NOW.getTime() + 60_000));
  assert.equal(result.targetTrafficPercentage, 0);
  assert.equal(result.reviewGate.independentReviewerVerified, true);
  assert.equal(Date.parse(result.expiresAt) - Date.parse(result.authorizedAt), CONTROL_CONTRACT.authorizationLifetimeMs);
  assertPolicyCode(() => validateAuthorizationRecord({ ...value, targetTrafficPercentage: 1 }, expected(), NOW), "deployment_target_invalid");
  assertPolicyCode(() => validateAuthorizationRecord({ ...value, expiresAt: "not-a-date" }, expected(), NOW), "authorization_time_invalid");
  assertPolicyCode(() => validateAuthorizationRecord(value, { ...expected(), sourceRevision: "2".repeat(40) }, NOW), "trusted_expectations_mismatch");
  assertPolicyCode(() => validateAuthorizationRecord({ ...value, unexpected: true }, expected(), NOW), "authorization_fields_invalid");
  assertPolicyCode(() => validateAuthorizationRecord(value, expected(), new Date(NOW.getTime() + CONTROL_CONTRACT.authorizationLifetimeMs)), "authorization_not_current");
});

test("Cosign commands pin exact issuer, identities, workflow claims and never use regex or bypasses", () => {
  const commands = candidateCosignCommands(candidate());
  const candidateText = Object.values(commands).flat().join(" ");
  for (const required of [
    CONTROL_CONTRACT.issuer,
    CONTROL_CONTRACT.publishWorkflowIdentity,
    CONTROL_CONTRACT.sourceRepository,
    CONTROL_CONTRACT.publishWorkflowRef,
    CONTROL_CONTRACT.publishEvent,
    PUBLISH_WORKFLOW_SHA,
    "--check-claims=true",
  ]) assert.match(candidateText, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(candidateText, /regexp|insecure-ignore|check-claims=false/);

  const blobText = authorizationCosignArgs(record(), "bundle.json").join(" ");
  assert.match(blobText, new RegExp(CONTROL_CONTRACT.authorizationWorkflowIdentity.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(blobText, new RegExp(AUTHORIZATION_WORKFLOW_SHA));
  assert.doesNotMatch(blobText, /regexp|insecure-ignore|check-claims=false/);
});

test("replay ledger consumes an authorization exactly once", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "omnisec-control-test-"));
  const ledger = path.join(root, "state", "consumed.json");
  try {
    await consumeAuthorizationId(ledger, AUTHORIZATION_ID);
    const stored = JSON.parse(await readFile(ledger, "utf8"));
    assert.deepEqual(stored.consumedAuthorizationIds, [AUTHORIZATION_ID]);
    await assert.rejects(() => consumeAuthorizationId(ledger, AUTHORIZATION_ID), (error) => error instanceof AuthorizationPolicyError && error.code === "authorization_replayed");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSON Schema requires exactly the generated authorization fields and immutable contract values", async () => {
  const schema = JSON.parse(await readFile(new URL("../schemas/deployment-authorization.schema.json", import.meta.url), "utf8"));
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual([...schema.required].sort(), Object.keys(record()).sort());
  assert.equal(schema.properties.targetTrafficPercentage.const, 0);
  assert.equal(schema.properties.controlRepository.const, CONTROL_CONTRACT.controlRepository);
  assert.equal(schema.properties.authorizationWorkflowIdentity.const, CONTROL_CONTRACT.authorizationWorkflowIdentity);
});

test("unexpected diagnostics are reduced to a safe sentinel", () => {
  assert.equal(safeErrorCode(new Error("raw command output must not escape")), "diagnostic_unavailable");
  assert.equal(safeErrorCode(new AuthorizationPolicyError("source_revision_invalid")), "source_revision_invalid");
});
