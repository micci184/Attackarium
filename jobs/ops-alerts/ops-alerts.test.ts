import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  DEFAULT_OPTIONS,
  buildSlackMessage,
  buildSlackTestMessage,
  evaluateAlerts,
  fetchSensors,
  isSlackWebhookUrl,
  planNotifications,
  postSlack,
  type AlertState,
  type SensorHealthRow,
} from "./core.ts";

const NOW = Date.parse("2026-12-10T12:00:00Z");
const minutesAgo = (m: number) => new Date(NOW - m * 60_000).toISOString();
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();
const MB = 1024 * 1024;
const opts = { ...DEFAULT_OPTIONS, nowMs: NOW };

const healthy: SensorHealthRow = {
  id: "sensor-a",
  is_active: true,
  last_heartbeat_at: minutesAgo(3),
  last_patch_success_at: daysAgo(1),
};

const active = (checks: ReturnType<typeof evaluateAlerts>) =>
  checks.filter((c) => c.active).map((c) => c.key).sort();

describe("evaluateAlerts", () => {
  it("is quiet for a healthy sensor and a small database", () => {
    assert.deepEqual(active(evaluateAlerts([healthy], 70 * MB, opts)), []);
  });

  it("flags a missing or never-reported heartbeat", () => {
    const checks = evaluateAlerts([{ ...healthy, last_heartbeat_at: minutesAgo(45) }], 70 * MB, opts);
    assert.deepEqual(active(checks), ["heartbeat_stale"]);
    assert.match(checks.find((c) => c.key === "heartbeat_stale")!.detail, /longest: 45 min/);
    assert.deepEqual(
      active(evaluateAlerts([{ ...healthy, last_heartbeat_at: null }], 70 * MB, opts)),
      ["heartbeat_stale"],
    );
    // Inactive sensors are ignored.
    assert.deepEqual(
      active(evaluateAlerts([healthy, { ...healthy, id: "old", is_active: false, last_heartbeat_at: null }], 70 * MB, opts)),
      [],
    );
  });

  it("compares the heartbeat age before rounding", () => {
    const at = (ms: number) => new Date(NOW - ms).toISOString();
    assert.deepEqual(active(evaluateAlerts([{ ...healthy, last_heartbeat_at: at(20 * 60_000) }], 70 * MB, opts)), []);
    assert.deepEqual(
      active(evaluateAlerts([{ ...healthy, last_heartbeat_at: at(20 * 60_000 + 1) }], 70 * MB, opts)),
      ["heartbeat_stale"],
    );
    assert.deepEqual(
      active(evaluateAlerts([{ ...healthy, last_heartbeat_at: at(20 * 60_000 + 30_000) }], 70 * MB, opts)),
      ["heartbeat_stale"],
    );
  });

  it("flags database storage at the threshold", () => {
    assert.deepEqual(active(evaluateAlerts([healthy], 349 * MB, opts)), []);
    const checks = evaluateAlerts([healthy], 350 * MB, opts);
    assert.deepEqual(active(checks), ["db_storage"]);
    assert.match(checks.find((c) => c.key === "db_storage")!.detail, /350 MB of 500 MB \(70%\)/);
  });

  it("flags stale OS updates and no active sensors", () => {
    assert.deepEqual(
      active(evaluateAlerts([{ ...healthy, last_patch_success_at: daysAgo(5) }], 70 * MB, opts)),
      ["patch_freshness"],
    );
    assert.deepEqual(active(evaluateAlerts([], 70 * MB, opts)), ["no_active_sensors"]);
  });
});

describe("planNotifications", () => {
  const firing = evaluateAlerts([{ ...healthy, last_heartbeat_at: minutesAgo(45) }], 70 * MB, opts);
  const quiet = evaluateAlerts([healthy], 70 * MB, opts);

  it("notifies once when an alert starts, not on every run", () => {
    const first = planNotifications(firing, [], NOW);
    assert.deepEqual(first.notifications.map((n) => [n.kind, n.check.key]), [["firing", "heartbeat_stale"]]);
    assert.equal(first.nextStates.length, 1);
    const second = planNotifications(firing, first.nextStates, NOW + 15 * 60_000);
    assert.equal(second.notifications.length, 0);
    assert.equal(second.nextStates.length, 0);
  });

  it("reminds daily while active and notifies once on resolve", () => {
    const state: AlertState[] = [
      { alert_key: "heartbeat_stale", active: true, since: daysAgo(2), last_notified_at: daysAgo(1) },
    ];
    assert.deepEqual(
      planNotifications(firing, state, NOW).notifications.map((n) => n.kind),
      ["reminder"],
    );
    const resolved = planNotifications(quiet, state, NOW);
    assert.deepEqual(resolved.notifications.map((n) => [n.kind, n.check.key]), [["resolved", "heartbeat_stale"]]);
    assert.equal(resolved.nextStates[0].active, false);
    // Already resolved: nothing more.
    assert.equal(planNotifications(quiet, resolved.nextStates, NOW + 60_000).notifications.length, 0);
  });

  it("creates no rows for alerts that were never active", () => {
    const plan = planNotifications(quiet, [], NOW);
    assert.deepEqual(plan, { notifications: [], nextStates: [] });
  });
});

describe("Slack delivery", () => {
  it("accepts only Slack incoming-webhook URLs", () => {
    assert.equal(isSlackWebhookUrl("https://hooks.slack.com/services/T000/B000/XXXX"), true);
    for (const bad of [
      "http://hooks.slack.com/services/T/B/X",
      "https://hooks.slack.com.evil.example/services/T/B/X",
      "https://example.com/services/T/B/X",
      "https://hooks.slack.com/other",
      "not a url",
      "",
    ]) {
      assert.equal(isSlackWebhookUrl(bad), false, bad);
    }
  });

  it("builds an explicit test message that implies no alert", () => {
    const text = buildSlackTestMessage(NOW).text;
    assert.match(text, /Test message/);
    assert.match(text, /no alert is implied/);
  });

  it("escapes Slack control characters and labels each kind", () => {
    const message = buildSlackMessage([
      { kind: "firing", check: { key: "db_storage", active: true, title: "A <b> & c", detail: "<!channel>" } },
      { kind: "resolved", check: { key: "heartbeat_stale", active: false, title: "Beat", detail: "ok" } },
    ]);
    assert.match(message.text, /ALERT/);
    assert.match(message.text, /RESOLVED/);
    assert.ok(!message.text.includes("<!channel>"));
    assert.ok(message.text.includes("&lt;!channel&gt;"));
  });

  it("refuses to post to a non-Slack URL and reports HTTP failures", async () => {
    let called = false;
    const fetchFn = (async () => {
      called = true;
      return new Response("", { status: 200 });
    }) as typeof fetch;
    await assert.rejects(postSlack("https://example.com/hook", { text: "x" }, fetchFn));
    assert.equal(called, false);
    const failing = (async () => new Response("", { status: 404 })) as typeof fetch;
    await assert.rejects(
      postSlack("https://hooks.slack.com/services/T/B/X", { text: "x" }, failing),
      /HTTP 404/,
    );
  });
});

describe("fetchSensors", () => {
  it("fails when the response may be truncated", async () => {
    const fetchFn = (async () =>
      new Response(JSON.stringify([{ id: "a", is_active: true }]), {
        status: 200,
        headers: { "content-range": "0-0/2" },
      })) as typeof fetch;
    await assert.rejects(fetchSensors("https://x.supabase.co", "k", fetchFn), /truncated/);
  });
});
