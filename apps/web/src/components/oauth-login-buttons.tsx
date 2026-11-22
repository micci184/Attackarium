"use client";

import { useState } from "react";

type OAuthProvider = "github" | "google";

type OAuthLoginButtonsProps = {
  nextPath: string;
  githubLabel?: string;
  googleLabel?: string;
  className?: string;
};

export function OAuthLoginButtons({
  nextPath,
  githubLabel = "Sign in with GitHub",
  googleLabel = "Sign in with Google",
  className = "flex flex-wrap gap-3",
}: OAuthLoginButtonsProps) {
  const [pendingProvider, setPendingProvider] = useState<OAuthProvider | null>(
    null,
  );
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  async function startSignIn(provider: OAuthProvider) {
    setPendingProvider(provider);
    setErrorMessage(null);

    try {
      const response = await fetch("/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ provider, next: nextPath }),
      });

      const payload = (await response.json().catch(() => null)) as {
        url?: unknown;
      } | null;

      if (
        !response.ok ||
        typeof payload?.url !== "string" ||
        (!payload.url.startsWith("https://") &&
          !payload.url.startsWith("http://"))
      ) {
        setErrorMessage(
          "Sign-in could not be started. Verify that the OAuth provider is enabled in Supabase Auth and try again.",
        );
        setPendingProvider(null);
        return;
      }

      window.location.assign(payload.url);
    } catch {
      setErrorMessage("Network error while starting sign-in. Please try again.");
      setPendingProvider(null);
    }
  }

  return (
    <div className="space-y-3">
      {errorMessage ? (
        <div
          role="alert"
          className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900"
        >
          {errorMessage}
        </div>
      ) : null}
      <div className={className}>
        <button
          type="button"
          disabled={pendingProvider !== null}
          onClick={() => void startSignIn("github")}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {pendingProvider === "github" ? "Redirecting…" : githubLabel}
        </button>
        <button
          type="button"
          disabled={pendingProvider !== null}
          onClick={() => void startSignIn("google")}
          className="rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-800 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {pendingProvider === "google" ? "Redirecting…" : googleLabel}
        </button>
      </div>
    </div>
  );
}
