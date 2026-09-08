import assert from "node:assert/strict";
import test from "node:test";

import { scanControlRepository } from "../scripts/static-security-check.mjs";

test("control repository static security contract passes", async () => {
  assert.deepEqual(await scanControlRepository(), { failures: [], workflows: 2 });
});
