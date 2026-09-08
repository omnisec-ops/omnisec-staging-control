import { readFile, writeFile } from "node:fs/promises";

import { buildAuthorizationRecord, safeErrorCode } from "./authorization-policy.mjs";

const [candidatePath, reviewProofPath, authorizationWorkflowSha, authorizationRunId, authorizationRunAttempt, outputPath] = process.argv.slice(2);

async function main() {
  if (![candidatePath, reviewProofPath, authorizationWorkflowSha, authorizationRunId, authorizationRunAttempt, outputPath].every(Boolean)) {
    throw new Error("arguments_missing");
  }
  const candidate = JSON.parse(await readFile(candidatePath, "utf8"));
  const reviewProof = JSON.parse(await readFile(reviewProofPath, "utf8"));
  const record = buildAuthorizationRecord({ candidate, reviewProof, authorizationWorkflowSha, authorizationRunId, authorizationRunAttempt });
  await writeFile(outputPath, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ status: "generated", authorizationId: record.authorizationId })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ status: "blocked", code: safeErrorCode(error) })}\n`);
  process.exitCode = 1;
});
