import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { handleOpsAlerts, secretsEqual, type HandlerEnv } from "./handler.ts";

const SECRET = "x".repeat(48);
const env: HandlerEnv = {
  supabaseUrl: "https://example.supabase.co",
  serviceRoleKey: "service",
  webhookUrl: "https://hooks.slack.com/services/T/B/X",
  cronSecret: SECRET,
};
const ok = async () => ({ checks: 4, active: 0, notified: 0, testSent: false });
const req = (init: RequestInit = {}) =>
  new Request("https://example.supabase.co/functions/v1/ops-alerts", { method: "POST", ...init });

describe("ops-alerts handler", () => {
  it("runs with the correct bearer secret and returns counts only", async () => {
    let calls = 0;
    const res = await handleOpsAlerts(req({ headers: { authorization: `Bearer ${SECRET}` } }), env, async (config) => {
      calls += 1;
      assert.equal(config.recordRunnerHeartbeat, true, "the primary runner must record its heartbeat");
      return ok();
    });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { checks: 4, active: 0, notified: 0, testSent: false });
    assert.equal(calls, 1);
  });

  it("rejects missing, wrong, or non-Bearer credentials without running", async () => {
    let calls = 0;
    const run = async () => {
      calls += 1;
      return ok();
    };
    for (const headers of [{}, { authorization: "Bearer wrong" }, { authorization: SECRET }, { authorization: `Basic ${SECRET}` }]) {
      assert.equal((await handleOpsAlerts(req({ headers }), env, run)).status, 401);
    }
    assert.equal(calls, 0);
  });

  it("refuses everything when the secret is not configured (never open)", async () => {
    for (const cronSecret of ["", "short"]) {
      const res = await handleOpsAlerts(req({ headers: { authorization: "Bearer " } }), { ...env, cronSecret }, ok);
      assert.equal(res.status, 503);
    }
  });

  it("allows POST only", async () => {
    const res = await handleOpsAlerts(
      new Request("https://x/functions/v1/ops-alerts", { method: "GET", headers: { authorization: `Bearer ${SECRET}` } }),
      env,
      ok,
    );
    assert.equal(res.status, 405);
  });

  it("hides failure details from the response", async () => {
    const res = await handleOpsAlerts(req({ headers: { authorization: `Bearer ${SECRET}` } }), env, async () => {
      throw new Error("Slack webhook failed with HTTP 404");
    });
    assert.equal(res.status, 500);
    assert.deepEqual(await res.json(), { error: "run_failed" });
  });

  it("compares secrets exactly", () => {
    assert.equal(secretsEqual("abc", "abc"), true);
    assert.equal(secretsEqual("abc", "abd"), false);
    assert.equal(secretsEqual("abc", "abcd"), false);
    assert.equal(secretsEqual("", ""), true);
  });
});
