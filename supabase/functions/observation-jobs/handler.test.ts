import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { handleObservationJobs, type JobsEnv, type JobRunner } from "./handler.ts";

const SECRET = "y".repeat(64);
const env: JobsEnv = { supabaseUrl: "https://example.supabase.co", serviceRoleKey: "service", cronSecret: SECRET };
const auth = { authorization: `Bearer ${SECRET}` };
const req = (body?: string, headers: Record<string, string> = auth, method = "POST") =>
  new Request("https://example.supabase.co/functions/v1/observation-jobs", { method, headers, body });

describe("observation-jobs handler", () => {
  it("runs only the named, allowlisted job and returns counts", async () => {
    const ran: string[] = [];
    const run: JobRunner = async (job) => {
      ran.push(job);
      return { eventsRead: 3 };
    };
    const res = await handleObservationJobs(req('{"job":"cve-matching"}'), env, run);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { job: "cve-matching", eventsRead: 3 });
    assert.equal((await handleObservationJobs(req('{"job":"threat-intel"}'), env, run)).status, 200);
    for (const body of [undefined, "{}", '{"job":"ops-alerts"}', '{"job":["cve-matching"]}', "nope"]) {
      assert.equal((await handleObservationJobs(req(body), env, run)).status, 400, String(body));
    }
    assert.deepEqual(ran, ["cve-matching", "threat-intel"]);
  });

  it("rejects bad credentials and refuses when the secret is unset, without running", async () => {
    let calls = 0;
    const run: JobRunner = async () => {
      calls += 1;
      return {};
    };
    const body = '{"job":"cve-matching"}';
    assert.equal((await handleObservationJobs(req(body, {}), env, run)).status, 401);
    assert.equal((await handleObservationJobs(req(body, { authorization: "Bearer wrong" }), env, run)).status, 401);
    assert.equal((await handleObservationJobs(req(body), { ...env, cronSecret: "" }, run)).status, 503);
    assert.equal((await handleObservationJobs(req(undefined, auth, "GET"), env, run)).status, 405);
    assert.equal(calls, 0);
  });

  it("hides failure details", async () => {
    const res = await handleObservationJobs(req('{"job":"threat-intel"}'), env, async () => {
      throw new Error("KEV feed HTTP 503 at https://example");
    });
    assert.equal(res.status, 500);
    assert.deepEqual(await res.json(), { job: "threat-intel", error: "run_failed" });
  });
});
