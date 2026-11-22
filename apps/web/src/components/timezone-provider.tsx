"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { formatUtcDateTime, formatUtcShort } from "@/lib/format";

export type TimezoneMode = "utc" | "local";

const STORAGE_KEY = "attackarium:tz:v1";

interface TimezoneContextValue {
  mode: TimezoneMode;
  setMode: (next: TimezoneMode) => void;
  localTzLabel: string;
}

const TimezoneContext = createContext<TimezoneContextValue>({
  mode: "utc",
  setMode: () => {},
  localTzLabel: "Local",
});

const listeners = new Set<() => void>();
let cachedLocalTzLabel: string | null = null;

function subscribeTimezone(onStoreChange: () => void): () => void {
  listeners.add(onStoreChange);
  const onStorage = (event: StorageEvent) => {
    if (event.key === STORAGE_KEY) {
      onStoreChange();
    }
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(onStoreChange);
    window.removeEventListener("storage", onStorage);
  };
}

function getClientTimezoneMode(): TimezoneMode {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === "local" || saved === "utc") {
      return saved;
    }
  } catch {
    // Ignore storage access errors in private browsing.
  }
  return "utc";
}

function getServerTimezoneMode(): TimezoneMode {
  return "utc";
}

function detectLocalTimezoneShortLabel(): string {
  if (cachedLocalTzLabel !== null) return cachedLocalTzLabel;
  try {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZoneName: "short",
    }).formatToParts(new Date());
    const tzName = parts.find((part) => part.type === "timeZoneName")?.value;
    if (tzName && tzName.trim().length > 0) {
      cachedLocalTzLabel = tzName.trim();
      return cachedLocalTzLabel;
    }
  } catch {
    // Fall back to generic label.
  }
  cachedLocalTzLabel = "Local";
  return cachedLocalTzLabel;
}

function getServerLocalTzLabel(): string {
  return "Local";
}

function noopSubscribe(): () => void {
  return () => {};
}

function formatLocalDateTime(
  isoString: string,
  variant: "datetime" | "short",
  tzLabel: string,
): string {
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return "—";
  const pad = (n: number) => String(n).padStart(2, "0");
  const year = date.getFullYear();
  const month = pad(date.getMonth() + 1);
  const day = pad(date.getDate());
  const hour = pad(date.getHours());
  const minute = pad(date.getMinutes());
  const second = pad(date.getSeconds());
  if (variant === "short") {
    return `${month}-${day} ${hour}:${minute} ${tzLabel}`;
  }
  return `${year}-${month}-${day} ${hour}:${minute}:${second} ${tzLabel}`;
}

export function TimezoneProvider({ children }: { children: ReactNode }) {
  const mode = useSyncExternalStore(
    subscribeTimezone,
    getClientTimezoneMode,
    getServerTimezoneMode,
  );
  const localTzLabel = useSyncExternalStore(
    noopSubscribe,
    detectLocalTimezoneShortLabel,
    getServerLocalTzLabel,
  );

  const setMode = useCallback((next: TimezoneMode) => {
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Ignore storage write errors.
    }
    for (const listener of listeners) {
      listener();
    }
  }, []);

  const value = useMemo(
    () => ({ mode, setMode, localTzLabel }),
    [mode, setMode, localTzLabel],
  );

  return (
    <TimezoneContext.Provider value={value}>
      {children}
    </TimezoneContext.Provider>
  );
}

export function useTimezone(): TimezoneContextValue {
  return useContext(TimezoneContext);
}

export function TimezoneToggle({ compact = false }: { compact?: boolean }) {
  const { mode, setMode, localTzLabel } = useTimezone();

  return (
    <div
      role="group"
      aria-label="Timestamp display timezone"
      className="inline-flex items-center rounded-md border border-slate-200 bg-slate-50 p-0.5 text-[11px] font-medium dark:border-slate-700 dark:bg-slate-900"
    >
      <button
        type="button"
        aria-pressed={mode === "utc"}
        onClick={() => setMode("utc")}
        className={`rounded px-2 py-0.5 font-mono transition-colors ${
          mode === "utc"
            ? "bg-white text-[#632ca6] shadow-2xs dark:bg-slate-800 dark:text-violet-200"
            : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
        }`}
      >
        UTC
      </button>
      <button
        type="button"
        aria-pressed={mode === "local"}
        onClick={() => setMode("local")}
        title={`Switch timestamps to local timezone (${localTzLabel})`}
        className={`rounded px-2 py-0.5 font-mono transition-colors ${
          mode === "local"
            ? "bg-white text-[#632ca6] shadow-2xs dark:bg-slate-800 dark:text-violet-200"
            : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
        }`}
      >
        <span suppressHydrationWarning>
          {compact ? "Local" : `Local (${localTzLabel})`}
        </span>
      </button>
    </div>
  );
}

export function TimezoneLabel() {
  const { mode, localTzLabel } = useTimezone();
  return <span suppressHydrationWarning>{mode === "utc" ? "UTC" : localTzLabel}</span>;
}

export function FormattedTime({
  iso,
  variant = "datetime",
  fallback = "—",
}: {
  iso: string | null | undefined;
  variant?: "datetime" | "short";
  fallback?: string;
}) {
  const { mode, localTzLabel } = useTimezone();

  if (!iso) {
    return <span>{fallback}</span>;
  }

  const formatted =
    mode === "local"
      ? formatLocalDateTime(iso, variant, localTzLabel)
      : variant === "short"
        ? formatUtcShort(iso)
        : formatUtcDateTime(iso);

  if (formatted === "—") {
    return <span>{fallback}</span>;
  }

  return (
    <time dateTime={iso} suppressHydrationWarning>
      {formatted}
    </time>
  );
}
