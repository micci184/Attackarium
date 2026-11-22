"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

type AdminMfaChallengeProps = {
  initialFactorId: string | null;
};

export function AdminMfaChallenge({ initialFactorId }: AdminMfaChallengeProps) {
  const router = useRouter();
  const [factorId, setFactorId] = useState<string | null>(initialFactorId);
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [pending, setPending] = useState<"enroll" | "verify" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  async function handleEnroll() {
    setPending("enroll");
    setErrorMessage(null);

    try {
      const response = await fetch("/api/admin/mfa/enroll", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({}),
      });

      const payload = (await response.json().catch(() => null)) as {
        alreadyEnrolled?: boolean;
        factorId?: unknown;
        qrCode?: unknown;
        secret?: unknown;
      } | null;

      if (!response.ok || typeof payload?.factorId !== "string") {
        setErrorMessage(
          "Could not start TOTP enrollment. Ensure TOTP MFA is enabled in Supabase Auth.",
        );
        setPending(null);
        return;
      }

      setFactorId(payload.factorId);
      if (
        !payload.alreadyEnrolled &&
        typeof payload.qrCode === "string" &&
        payload.qrCode.startsWith("data:image/svg+xml")
      ) {
        setQrCode(payload.qrCode);
      }
      if (typeof payload.secret === "string") {
        setSecret(payload.secret);
      }
      setPending(null);
    } catch {
      setErrorMessage("Network error while starting MFA enrollment.");
      setPending(null);
    }
  }

  async function handleVerify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!factorId) return;

    const cleanCode = code.replace(/\s+/g, "");
    if (!/^\d{6}$/.test(cleanCode)) {
      setErrorMessage("Enter the 6-digit code from your authenticator app.");
      return;
    }

    setPending("verify");
    setErrorMessage(null);

    try {
      const response = await fetch("/api/admin/mfa/verify", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ factorId, code: cleanCode }),
      });

      const payload = (await response.json().catch(() => null)) as {
        ok?: boolean;
        redirectTo?: unknown;
      } | null;

      if (!response.ok || !payload?.ok) {
        setErrorMessage(
          "Invalid or expired 6-digit code. Check your authenticator app and try again.",
        );
        setPending(null);
        return;
      }

      router.push("/admin");
      router.refresh();
    } catch {
      setErrorMessage("Network error while verifying MFA code.");
      setPending(null);
    }
  }

  return (
    <div className="mt-5 space-y-5">
      {errorMessage ? (
        <div
          role="alert"
          className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900"
        >
          {errorMessage}
        </div>
      ) : null}

      {!factorId ? (
        <div className="space-y-3">
          <p className="text-sm text-slate-600">
            No verified TOTP authenticator is enrolled on your operator account
            yet. Enroll an authenticator app (Google Authenticator, 1Password,
            Authy, etc.) to elevate this session to{" "}
            <code className="font-mono text-xs">aal2</code>.
          </p>
          <button
            type="button"
            disabled={pending !== null}
            onClick={() => void handleEnroll()}
            className="rounded-md bg-[#632ca6] px-4 py-2 text-sm font-medium text-white hover:bg-[#53238d] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {pending === "enroll"
              ? "Generating QR code…"
              : "Set up authenticator app (TOTP)"}
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {qrCode ? (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
              <p className="text-xs font-medium text-slate-700">
                1. Scan this QR code in your authenticator app
              </p>
              <div className="mt-3 inline-block rounded-lg bg-white p-3 ring-1 ring-slate-200">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={qrCode}
                  alt="TOTP authenticator QR code"
                  width={180}
                  height={180}
                />
              </div>
              {secret ? (
                <p className="mt-3 break-all text-xs text-slate-600">
                  Manual key:{" "}
                  <code className="rounded bg-white px-1.5 py-0.5 font-mono text-slate-900 ring-1 ring-slate-200">
                    {secret}
                  </code>
                </p>
              ) : null}
            </div>
          ) : null}

          <form onSubmit={(event) => void handleVerify(event)} className="space-y-3">
            <label className="block text-xs font-medium text-slate-700">
              {qrCode
                ? "2. Enter the 6-digit code to finish enrollment"
                : "Enter the 6-digit code from your authenticator app"}
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                pattern="\d{6}"
                required
                value={code}
                onChange={(event) => setCode(event.target.value)}
                placeholder="123456"
                className="mt-1.5 block w-44 rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-base tracking-widest text-slate-900 focus:border-[#632ca6] focus:outline-none"
              />
            </label>
            <button
              type="submit"
              disabled={pending !== null}
              className="rounded-md bg-[#632ca6] px-4 py-2 text-sm font-medium text-white hover:bg-[#53238d] disabled:cursor-not-allowed disabled:opacity-60"
            >
              {pending === "verify"
                ? "Verifying…"
                : "Verify MFA and open Admin Console"}
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
