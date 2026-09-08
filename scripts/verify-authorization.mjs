import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";

import {
  authorizationCosignArgs,
  candidateCosignCommands,
  consumeAuthorizationId,
  safeErrorCode,
  validateAuthorizationRecord,
  validateCandidateAttestations,
} from "./authorization-policy.mjs";

const [recordPath, bundlePath, replayLedgerPath, authorizationWorkflowSha, sourceRevision, backendImage, frontendImage] = process.argv.slice(2);
const EXECUTION_LIMIT = 1024 * 1024;

function runCosign(args, capture = false) {
  return execFileSync("cosign", args, {
    encoding: capture ? "utf8" : undefined,
    maxBuffer: EXECUTION_LIMIT,
    stdio: capture ? ["ignore", "pipe", "ignore"] : ["ignore", "ignore", "ignore"],
  });
}

async function main() {
  if (![recordPath, bundlePath, replayLedgerPath, authorizationWorkflowSha, sourceRevision, backendImage, frontendImage].every(Boolean)) throw new Error("arguments_missing");
  const recordRaw = await readFile(recordPath, "utf8");
  if (Buffer.byteLength(recordRaw, "utf8") > EXECUTION_LIMIT) throw new Error("record_too_large");
  const record = validateAuthorizationRecord(
    JSON.parse(recordRaw),
    { authorizationWorkflowSha, sourceRevision, backendImage, frontendImage },
  );
  runCosign([...authorizationCosignArgs(record, bundlePath), recordPath]);
  const candidate = {
    sourceRevision: record.sourceRevision,
    sourceStateHash: record.sourceStateHash,
    manifestSha256: record.manifestSha256,
    publishWorkflowSha: record.publishWorkflowSha,
    backendImage: record.backendImage,
    frontendImage: record.frontendImage,
  };
  const commands = candidateCosignCommands(candidate);
  runCosign(commands.backendSignature);
  runCosign(commands.frontendSignature);
  const backendOutput = runCosign(commands.backendAttestation, true);
  const frontendOutput = runCosign(commands.frontendAttestation, true);
  validateCandidateAttestations({ candidate, backendOutput, frontendOutput });
  await consumeAuthorizationId(replayLedgerPath, record.authorizationId);
  process.stdout.write(`${JSON.stringify({ status: "verified-and-consumed", authorizationId: record.authorizationId, targetTrafficPercentage: 0 })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ status: "blocked", code: safeErrorCode(error) })}\n`);
  process.exitCode = 1;
});
