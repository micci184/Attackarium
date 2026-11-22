"use client";

import { useState } from "react";

type ConsentDecision = "approve" | "deny";

type OAuthConsentActionsProps = {
  authorizationId: string;
};

export function OAuthConsentActions({
  authorizationId,
}: OAuthConsentActionsProps) {
  const [pendingDecision, setPendingDecision] =
    useState<ConsentDecision | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  async function submitDecision(decision: ConsentDecision) {
    setPendingDecision(decision);
    setErrorMessage(null);

    try {
      const response = await fetch("/auth/oauth/decision", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          authorization_id: authorizationId,
          decision,
        }),
      });

      const payload = (await response.json().catch(() => null)) as {
        redirect_url?: unknown;
      } | null;

      const redirectUrl =
        typeof payload?.redirect_url === "string"
          ? payload.redirect_url.trim()
          : "";
      const lowerUrl = redirectUrl.toLowerCase();

      if (
        !response.ok ||
        !redirectUrl ||
        lowerUrl.startsWith("javascript:") ||
        lowerUrl.startsWith("data:")
      ) {
        setErrorMessage(
          "Could not complete the authorization decision. Restart the connection from your MCP client.",
        );
        setPendingDecision(null);
        return;
      }

      window.location.assign(redirectUrl);
    } catch {
      setErrorMessage(
        "Network error while submitting authorization decision. Please try again.",
      );
      setPendingDecision(null);
    }
  }

  return (
    <div className="mt-5 space-y-3">
      {errorMessage ? (
        <div
          role="alert"
          className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900"
        >
          {errorMessage}
        </div>
      ) : null}
      <div className="flex flex-wrap gap-3">
        <button
          type="button"
          disabled={pendingDecision !== null}
          onClick={() => void submitDecision("approve")}
          className="rounded-md bg-[#632ca6] px-4 py-2 text-sm font-medium text-white hover:bg-[#53238d] disabled:cursor-not-allowed disabled:opacity-60"
        >
          {pendingDecision === "approve"
            ? "Approving…"
            : "Approve read-only access"}
        </button>
        <button
          type="button"
          disabled={pendingDecision !== null}
          onClick={() => void submitDecision("deny")}
          className="rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {pendingDecision === "deny" ? "Denying…" : "Deny"}
        </button>
      </div>
    </div>
  );
}
