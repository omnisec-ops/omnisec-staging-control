import { writeFile } from "node:fs/promises";

import { safeErrorCode, validateReviewHistory } from "./authorization-policy.mjs";

const [outputPath] = process.argv.slice(2);
const MAX_RESPONSE_BYTES = 1024 * 1024;

async function main() {
  const token = process.env.GITHUB_TOKEN;
  const repository = process.env.GITHUB_REPOSITORY;
  const workflowRunId = process.env.GITHUB_RUN_ID;
  const initiatorLogin = process.env.GITHUB_ACTOR;
  const initiatorId = process.env.GITHUB_ACTOR_ID;
  if (!outputPath || !token || !repository || !workflowRunId || !initiatorLogin || !initiatorId) throw new Error("review_context_missing");
  const response = await fetch(`https://api.github.com/repos/${repository}/actions/runs/${workflowRunId}/approvals`, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
    redirect: "error",
  });
  if (!response.ok) throw new Error("review_api_unavailable");
  const raw = await response.text();
  if (Buffer.byteLength(raw, "utf8") > MAX_RESPONSE_BYTES) throw new Error("review_api_response_too_large");
  const proof = validateReviewHistory({ raw, initiatorLogin, initiatorId, workflowRunId });
  await writeFile(outputPath, `${JSON.stringify(proof, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ status: "verified", independentReviewerVerified: true })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${JSON.stringify({ status: "blocked", code: safeErrorCode(error) })}\n`);
  process.exitCode = 1;
});
