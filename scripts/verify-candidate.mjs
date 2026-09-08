import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";

import { candidateCosignCommands, safeErrorCode, validateCandidateAttestations, validateCandidateInput } from "./authorization-policy.mjs";

const [sourceRevision, sourceStateHash, manifestSha256, publishWorkflowSha, backendImage, frontendImage, outputPath] = process.argv.slice(2);
const EXECUTION_LIMIT = 1024 * 1024;

function runCosign(args, capture = false) {
  return execFileSync("cosign", args, {
    encoding: capture ? "utf8" : undefined,
    maxBuffer: EXECUTION_LIMIT,
    stdio: capture ? ["ignore", "pipe", "ignore"] : ["ignore", "ignore", "ignore"],
  });
}

async function main() {
  if (!outputPath) throw new Error("arguments_missing");
  const candidate = validateCandidateInput({ sourceRevision, sourceStateHash, manifestSha256, publishWorkflowSha, backendImage, frontendImage });
  const commands = candidateCosignCommands(candidate);
  runCosign(commands.backendSignature);
  runCosign(commands.frontendSignature);
  const backendOutput = runCosign(commands.backendAttestation, true);
  const frontendOutput = runCosign(commands.frontendAttestation, true);
  const verified = validateCandidateAttestations({ candidate, backendOutput, frontendOutput });
  await writeFile(outputPath, `${JSON.stringify(verified, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ status: "verified", sourceRevision: candidate.sourceRevision })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ status: "blocked", code: safeErrorCode(error) })}\n`);
  process.exitCode = 1;
});
