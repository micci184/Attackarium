"""Tests for record_os_update_status.sh (ADR-027) using temporary files only."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "record_os_update_status.sh"
NOW = 1_795_640_000  # fixed "now" for the script

OK_UPGRADE = (
    "2026-11-26 06:39:21,276 INFO Starting unattended upgrades script\n"
    "2026-11-26 06:39:21,277 INFO Allowed origins are: o=Ubuntu,a=noble-security\n"
    "2026-11-26 06:39:40,594 INFO All upgrades installed\n"
)
OK_NOTHING = (
    "2026-11-26 06:39:21,276 INFO Starting unattended upgrades script\n"
    "2026-11-26 06:39:21,645 INFO No packages found that can be upgraded unattended and no pending auto-removals\n"
)


class RecordOsUpdateStatusTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.stamp = self.tmp / "update-success-stamp"
        self.log = self.tmp / "unattended-upgrades.log"
        self.state = self.tmp / "state"

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def run_script(
        self,
        *,
        stamp_age: int | None = 3600,
        log: str | None = OK_UPGRADE,
        extra_env: dict[str, str] | None = None,
    ):
        if stamp_age is not None:
            self.stamp.touch()
            os.utime(self.stamp, (NOW - stamp_age, NOW - stamp_age))
        if log is not None:
            self.log.write_text(log)
        env = {
            **os.environ,
            "OS_UPDATE_STATE_DIR": str(self.state),
            "OS_UPDATE_LIST_STAMP": str(self.stamp),
            "OS_UPDATE_UU_LOG": str(self.log),
            "OS_UPDATE_NOW": str(NOW),
            **(extra_env or {}),
        }
        return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30)

    def recorded(self) -> dict[str, str] | None:
        path = self.state / "last-success"
        if not path.exists():
            return None
        return dict(line.split("=", 1) for line in path.read_text().splitlines())

    def test_records_success_after_clean_upgrade(self) -> None:
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rec = self.recorded()
        assert rec is not None
        self.assertEqual(rec["result"], "success")
        self.assertEqual(rec["detail"], "unattended-upgrades")
        # The run's own completion time, not "now".
        self.assertEqual(rec["finished_at"], "2026-11-26T06:39:40Z")

    def test_records_success_when_nothing_to_upgrade(self) -> None:
        proc = self.run_script(log=OK_NOTHING)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIsNotNone(self.recorded())

    def test_only_the_latest_run_counts(self) -> None:
        log = OK_UPGRADE + "2026-11-27 06:39:21,276 INFO Starting unattended upgrades script\n"
        proc = self.run_script(log=log)  # latest run never completed
        self.assertNotEqual(proc.returncode, 0)
        self.assertIsNone(self.recorded())

    def test_stale_or_missing_lists_are_not_success(self) -> None:
        proc = self.run_script(stamp_age=30 * 3600)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("stale", proc.stderr)
        self.assertIsNone(self.recorded())
        self.stamp.unlink()
        proc = self.run_script(stamp_age=None)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIsNone(self.recorded())

    def test_errors_in_the_latest_run_are_not_success(self) -> None:
        for bad in (
            OK_UPGRADE.replace("All upgrades installed", "All upgrades installed")
            + "2026-11-26 06:39:41,000 ERROR Installing the upgrades failed!\n",
            OK_UPGRADE + "Traceback (most recent call last):\n",
            "2026-11-26 06:39:21,276 INFO Starting unattended upgrades script\n",
            "",
        ):
            self.state.mkdir(exist_ok=True)
            (self.state / "last-success").unlink(missing_ok=True)
            proc = self.run_script(log=bad)
            self.assertNotEqual(proc.returncode, 0, bad)
            self.assertIsNone(self.recorded(), bad)

    def test_skipped_run_does_not_advance_the_status(self) -> None:
        self.assertEqual(self.run_script().returncode, 0)
        first = (self.state / "last-success").read_text()
        # apt-daily-upgrade skipped unattended-upgrade: same log, fresh lists.
        proc = self.run_script(stamp_age=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("no newer completed run", proc.stderr)
        self.assertEqual((self.state / "last-success").read_text(), first)

    def test_newer_manual_window_is_not_overwritten_by_an_older_run(self) -> None:
        self.state.mkdir()
        newer = "finished_at=2026-11-27T00:00:00Z\nresult=success\ndetail=security updates applied\n"
        (self.state / "last-success").write_text(newer)
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((self.state / "last-success").read_text(), newer)

    def test_a_newer_completed_run_advances_the_status(self) -> None:
        self.assertEqual(self.run_script().returncode, 0)
        later = OK_UPGRADE + OK_NOTHING.replace("2026-11-26", "2026-11-27")
        self.assertEqual(self.run_script(log=later).returncode, 0)
        self.assertEqual(self.recorded()["finished_at"], "2026-11-27T06:39:21Z")

    @unittest.skipUnless(shutil.which("flock"), "flock (util-linux) not installed")
    def test_waits_out_or_skips_while_a_patch_window_holds_the_lock(self) -> None:
        self.state.mkdir()
        holder = subprocess.Popen(
            ["flock", str(self.state / "run.lock"), "sleep", "3"],
        )
        try:
            time.sleep(0.3)
            env_extra = {"OS_UPDATE_LOCK_WAIT_SECONDS": "1"}
            proc = self.run_script(extra_env=env_extra)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("holds the lock", proc.stderr)
            self.assertIsNone(self.recorded())
        finally:
            holder.wait(timeout=10)

    def test_failure_keeps_an_older_success_untouched(self) -> None:
        self.state.mkdir()
        older = "finished_at=2026-11-01T00:00:00Z\nresult=success\ndetail=patch-window\n"
        (self.state / "last-success").write_text(older)
        proc = self.run_script(stamp_age=40 * 3600)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual((self.state / "last-success").read_text(), older)


if __name__ == "__main__":
    unittest.main()
