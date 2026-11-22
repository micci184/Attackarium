import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  evaluateOperatorAdmin,
  parseAdminAllowedUserIds,
  summarizeMcpUsageBuckets,
  type McpUsageBucketRow,
} from "./admin-auth-core.ts";

const OPERATOR_ID = "11111111-1111-4111-8111-111111111111";
const GENERAL_USER_ID = "22222222-2222-4222-8222-222222222222";

describe("operator admin authorization (default-deny + allowlist + MFA aal2)", () => {
  it("parses only valid UUIDs and defaults to empty (default-deny)", () => {
    assert.equal(parseAdminAllowedUserIds(undefined).size, 0);
    assert.equal(parseAdminAllowedUserIds("").size, 0);
    assert.equal(parseAdminAllowedUserIds("not-a-uuid, 12345").size, 0);

    const parsed = parseAdminAllowedUserIds(
      ` ${OPERATOR_ID.toUpperCase()} , invalid-id `,
    );
    assert.equal(parsed.size, 1);
    assert.equal(parsed.has(OPERATOR_ID), true);
  });

  it("denies unauthenticated users with 401", () => {
    const allowed = parseAdminAllowedUserIds(OPERATOR_ID);
    assert.deepEqual(evaluateOperatorAdmin(null, allowed), {
      ok: false,
      status: 401,
      reason: "unauthenticated",
    });
  });

  it("denies everyone when ADMIN_ALLOWED_USER_IDS is empty (default-deny)", () => {
    const allowed = parseAdminAllowedUserIds("");
    assert.deepEqual(
      evaluateOperatorAdmin({ userId: OPERATOR_ID, aal: "aal2" }, allowed),
      {
        ok: false,
        status: 403,
        reason: "not_allowlisted",
      },
    );
  });

  it("denies general users not in the allowlist even with aal2 MFA", () => {
    const allowed = parseAdminAllowedUserIds(OPERATOR_ID);
    assert.deepEqual(
      evaluateOperatorAdmin({ userId: GENERAL_USER_ID, aal: "aal2" }, allowed),
      {
        ok: false,
        status: 403,
        reason: "not_allowlisted",
      },
    );
  });

  it("denies allowlisted operators who have not completed MFA (aal1 or null)", () => {
    const allowed = parseAdminAllowedUserIds(OPERATOR_ID);
    assert.deepEqual(
      evaluateOperatorAdmin({ userId: OPERATOR_ID, aal: "aal1" }, allowed),
      {
        ok: false,
        status: 403,
        reason: "mfa_required",
      },
    );
    assert.deepEqual(
      evaluateOperatorAdmin({ userId: OPERATOR_ID, aal: null }, allowed),
      {
        ok: false,
        status: 403,
        reason: "mfa_required",
      },
    );
  });

  it("allows an allowlisted operator with verified aal2 MFA", () => {
    const allowed = parseAdminAllowedUserIds(OPERATOR_ID);
    assert.deepEqual(
      evaluateOperatorAdmin(
        { userId: OPERATOR_ID.toUpperCase(), aal: "aal2" },
        allowed,
      ),
      {
        ok: true,
        userId: OPERATOR_ID,
      },
    );
  });
});

describe("summarizeMcpUsageBuckets", () => {
  it("separates initialize from tool_call and computes top tools and latency safely", () => {
    const rows: McpUsageBucketRow[] = [
      {
        bucket_start: "2026-11-22T00:00:00Z",
        granularity: "hour",
        request_kind: "initialize",
        tool_name: "",
        call_count: 5,
        success_count: 5,
        error_count: 0,
        auth_failure_count: 3,
        rate_limited_count: 1,
        total_latency_ms: 100,
        active_user_count: 2,
      },
      {
        bucket_start: "2026-11-22T00:00:00Z",
        granularity: "hour",
        request_kind: "tool_call",
        tool_name: "get_observation_summary",
        call_count: 10,
        success_count: 9,
        error_count: 1,
        auth_failure_count: 0,
        rate_limited_count: 2,
        total_latency_ms: 1200,
        active_user_count: 4,
      },
      {
        bucket_start: "2026-11-22T00:00:00Z",
        granularity: "hour",
        request_kind: "tool_call",
        tool_name: "get_attack_trends",
        call_count: 5,
        success_count: 5,
        error_count: 0,
        auth_failure_count: 0,
        rate_limited_count: 0,
        total_latency_ms: 700,
        active_user_count: 3,
      },
    ];

    const summary = summarizeMcpUsageBuckets(rows);
    assert.equal(summary.initializeCalls, 5);
    assert.equal(summary.toolCalls, 15);
    assert.equal(summary.successCount, 19);
    assert.equal(summary.errorCount, 1);
    assert.equal(summary.successRatePct, 95);
    assert.equal(summary.errorRatePct, 5);
    assert.equal(summary.avgLatencyMs, 100);
    assert.equal(summary.authFailureCount, 3);
    assert.equal(summary.rateLimitedCount, 3);
    assert.equal(summary.peakActiveUsers, 4);
    assert.deepEqual(
      summary.topTools.map((t) => [t.toolName, t.callCount, t.avgLatencyMs]),
      [
        ["get_observation_summary", 10, 120],
        ["get_attack_trends", 5, 140],
      ],
    );
  });

  it("handles empty bucket lists without dividing by zero", () => {
    const summary = summarizeMcpUsageBuckets([]);
    assert.equal(summary.initializeCalls, 0);
    assert.equal(summary.toolCalls, 0);
    assert.equal(summary.successRatePct, null);
    assert.equal(summary.errorRatePct, null);
    assert.equal(summary.avgLatencyMs, null);
  });
});
