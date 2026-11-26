"""Tests for record_os_update_status.sh (ADR-027) using temporary files and a stub apt-get."""

from __future__ import annotations

import datetime as dt
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "record_os_update_status.sh"


def epoch(iso: str) -> int:
    return int(dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp())


REFRESH_DAY1 = epoch("2026-11-26T06:30:00Z")
REFRESH_DAY2 = epoch("2026-11-27T06:30:00Z")

RUN_DAY1 = (
    "2026-11-26 06:39:21,276 INFO Starting unattended upgrades script\n"
    "2026-11-26 06:39:21,277 INFO Allowed origins are: o=Ubuntu,a=noble-security\n"
    "2026-11-26 06:39:40,594 INFO All upgrades installed\n"
)
RUN_DAY2_NOTHING = (
    "2026-11-27 06:39:21,276 INFO Starting unattended upgrades script\n"
    "2026-11-27 06:39:21,645 INFO No packages found that can be upgraded unattended and no pending auto-removals\n"
)


class RecordOsUpdateStatusTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.log = self.tmp / "unattended-upgrades.log"
        self.state = self.tmp / "state"
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        apt = self.bin / "apt-get"
        apt.write_text('#!/bin/sh\necho "apt-get $*" >> "$STUB_LOG"\nexit "${STUB_APT_RC:-0}"\n')
        apt.chmod(apt.stat().st_mode | stat.S_IXUSR)
        self.calls = self.tmp / "calls.log"

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def run_phase(self, phase: str, *, now: int, apt_rc: int = 0, extra_env: dict[str, str] | None = None):
        env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "STUB_LOG": str(self.calls),
            "STUB_APT_RC": str(apt_rc),
            "OS_UPDATE_STATE_DIR": str(self.state),
            "OS_UPDATE_UU_LOG": str(self.log),
            "OS_UPDATE_NOW": str(now),
            **(extra_env or {}),
        }
        return subprocess.run(["bash", str(SCRIPT), phase], env=env, capture_output=True, text=True, timeout=30)

    def day(self, *, refresh_at: int, run_log: str, apt_rc: int = 0):
        """One apt-daily-upgrade invocation: refresh (pre), then record (post)."""
        self.assertEqual(self.run_phase("refresh", now=refresh_at, apt_rc=apt_rc).returncode, 0)
        self.log.write_text(run_log)
        return self.run_phase("record", now=refresh_at + 900)

    def recorded(self) -> dict[str, str] | None:
        path = self.state / "last-success"
        if not path.exists():
            return None
        return dict(line.split("=", 1) for line in path.read_text().splitlines())

    # --- refresh phase ---------------------------------------------------------

    def test_refresh_records_the_attempt_outcome_from_the_exit_status(self) -> None:
        self.run_phase("refresh", now=REFRESH_DAY1, apt_rc=0)
        self.assertIn("APT::Update::Error-Mode=any", self.calls.read_text())
        self.assertIn("result=ok", (self.state / "refresh-result").read_text())
        proc = self.run_phase("refresh", now=REFRESH_DAY2, apt_rc=100)
        self.assertEqual(proc.returncode, 0, "refresh must never block the upgrade")
        self.assertEqual(
            (self.state / "refresh-result").read_text(), f"result=failed\nat={REFRESH_DAY2}\n"
        )

    # --- record phase: success ---------------------------------------------------

    def test_records_the_runs_own_completion_time_after_a_clean_day(self) -> None:
        proc = self.day(refresh_at=REFRESH_DAY1, run_log=RUN_DAY1)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rec = self.recorded()
        assert rec is not None
        self.assertEqual(rec["finished_at"], "2026-11-26T06:39:40Z")
        self.assertEqual(rec["result"], "success")
        self.assertEqual(rec["detail"], "unattended-upgrades")

    def test_a_newer_clean_day_advances_the_status(self) -> None:
        self.day(refresh_at=REFRESH_DAY1, run_log=RUN_DAY1)
        proc = self.day(refresh_at=REFRESH_DAY2, run_log=RUN_DAY1 + RUN_DAY2_NOTHING)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.recorded()["finished_at"], "2026-11-27T06:39:21Z")

    # --- record phase: refusals --------------------------------------------------

    def test_failed_latest_refresh_blocks_success_even_after_a_good_one(self) -> None:
        # Day 1 good. Day 2: the refresh fails, the upgrade still completes.
        self.day(refresh_at=REFRESH_DAY1, run_log=RUN_DAY1)
        first = (self.state / "last-success").read_text()
        proc = self.day(refresh_at=REFRESH_DAY2, run_log=RUN_DAY1 + RUN_DAY2_NOTHING, apt_rc=100)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refresh failed", proc.stderr)
        self.assertEqual((self.state / "last-success").read_text(), first)

    def test_failed_refresh_with_no_previous_success_writes_nothing(self) -> None:
        proc = self.day(refresh_at=REFRESH_DAY1, run_log=RUN_DAY1, apt_rc=100)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIsNone(self.recorded())

    def test_no_refresh_attempt_recorded_writes_nothing(self) -> None:
        self.log.write_text(RUN_DAY1)
        proc = self.run_phase("record", now=REFRESH_DAY1 + 900)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIsNone(self.recorded())

    def test_skipped_upgrade_cannot_reuse_an_older_run(self) -> None:
        # Day 2 refresh succeeds but unattended-upgrade did not run: the latest
        # run in the log is day 1, before this refresh.
        self.day(refresh_at=REFRESH_DAY1, run_log=RUN_DAY1)
        first = (self.state / "last-success").read_text()
        proc = self.day(refresh_at=REFRESH_DAY2, run_log=RUN_DAY1)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("does not follow the latest refresh", proc.stderr)
        self.assertEqual((self.state / "last-success").read_text(), first)

    def test_run_long_after_the_refresh_is_not_this_invocation(self) -> None:
        proc = self.day(refresh_at=REFRESH_DAY1 - 7 * 3600, run_log=RUN_DAY1)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIsNone(self.recorded())

    def test_errors_or_incomplete_latest_run_are_not_success(self) -> None:
        for bad in (
            RUN_DAY1 + "2026-11-26 06:39:41,000 ERROR Installing the upgrades failed!\n",
            RUN_DAY1 + "Traceback (most recent call last):\n",
            RUN_DAY1.replace(
                "All upgrades installed",
                "Package openssh-server has conffile prompt and needs to be upgraded manually",
            )
            + "2026-11-26 06:39:40,600 INFO All upgrades installed\n",
            RUN_DAY1 + "2026-11-26 06:40:00,000 INFO Starting unattended upgrades script\n",
            "",
        ):
            (self.state / "last-success").unlink(missing_ok=True)
            proc = self.day(refresh_at=REFRESH_DAY1, run_log=bad)
            self.assertNotEqual(proc.returncode, 0, bad)
            self.assertIsNone(self.recorded(), bad)

    def test_newer_manual_window_is_not_overwritten(self) -> None:
        self.state.mkdir()
        newer = "finished_at=2026-11-27T00:00:00Z\nresult=success\ndetail=security updates applied\n"
        (self.state / "last-success").write_text(newer)
        proc = self.day(refresh_at=REFRESH_DAY1, run_log=RUN_DAY1)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((self.state / "last-success").read_text(), newer)

    @unittest.skipUnless(shutil.which("flock"), "flock (util-linux) not installed")
    def test_skips_while_a_patch_window_holds_the_lock(self) -> None:
        self.run_phase("refresh", now=REFRESH_DAY1)
        self.log.write_text(RUN_DAY1)
        acquired = self.tmp / "acquired"
        release = self.tmp / "release"
        holder = subprocess.Popen(
            [
                "flock",
                str(self.state / "run.lock"),
                "sh",
                "-c",
                f'touch "{acquired}"; while [ ! -f "{release}" ]; do sleep 0.05; done',
            ]
        )
        try:
            deadline = time.monotonic() + 10
            while not acquired.exists():
                self.assertLess(time.monotonic(), deadline, "lock holder never started")
                time.sleep(0.02)
            proc = self.run_phase(
                "record", now=REFRESH_DAY1 + 900, extra_env={"OS_UPDATE_LOCK_WAIT_SECONDS": "1"}
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("holds the lock", proc.stderr)
            self.assertIsNone(self.recorded())
        finally:
            release.touch()
            holder.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
