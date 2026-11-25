"""Tests for patch_sensor.sh with stubbed terraform, aws, ssh, and scp.

No AWS, Terraform state, or host is touched: every external command is a stub
on PATH that records its arguments and answers from environment variables.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "patch_sensor.sh"

STATUS_OK = (
    "finished_at=2026-11-25T07:00:17Z\nresult=success\ndetail=security updates applied\n"
    "reboot_required=${STUB_REBOOT_REQUIRED:-no}\napt_lists_refreshed_at=2026-11-25T06:59:26Z\n"
    "temporary_rule=${STUB_TEMP_RULE:-absent}\n"
)

STUBS = {
    "terraform": r"""
        #!/usr/bin/env bash
        args=("$@")
        [[ "${args[0]}" == -chdir=* ]] && args=("${args[@]:1}")
        echo "terraform ${args[*]}" >> "$STUB_LOG"
        case "${args[0]}" in
          console)
            expr="$(cat)"
            case "$expr" in
              *length*) echo "${STUB_TF_PATCH_LEN:-0}" ;;
              *aws_region*) echo '"us-east-1"' ;;
              *admin_ssh_port*) echo "3389" ;;
            esac ;;
          output) printf 'i-0123456789abcdef0' ;;
          plan)
            n=$(cat "$STUB_STATE/plans" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$STUB_STATE/plans"
            if [[ "$n" == "1" ]]; then exit "${STUB_TF_PREFLIGHT_RC:-0}"; fi
            exit "${STUB_TF_VERIFY_RC:-0}" ;;
          apply)
            if [[ "${args[*]}" == *"patch_egress_cidrs=[]"* ]]; then
              exit "${STUB_TF_CLOSE_RC:-0}"
            fi
            exit "${STUB_TF_OPEN_RC:-0}" ;;
        esac
    """,
    "aws": r"""
        #!/usr/bin/env bash
        echo "aws $*" >> "$STUB_LOG"
        case "$1 $2" in
          "sts get-caller-identity") echo "arn:aws:iam::000000000000:user/test" ;;
          "ec2 describe-instances") echo "vol-0abc" ;;
          "ec2 create-snapshot") echo "snap-0aaa111" ;;
          "ec2 describe-snapshots") echo "${STUB_EXPIRED:-}" ;;
          "ec2 delete-snapshot") ;;
        esac
    """,
    "ssh": r"""
        #!/usr/bin/env bash
        cmd="${@: -1}"
        echo "ssh $cmd" >> "$STUB_LOG"
        case "$cmd" in
          *"patch_window.sh resolve"*) printf '%b' "${STUB_RESOLVE:-104.20.28.246/32\n172.66.152.176/32\n}" ;;
          *"patch_window.sh run"*)
            [[ -n "${STUB_RUN_SLEEP:-}" ]] && sleep "$STUB_RUN_SLEEP"
            exit "${STUB_RUN_RC:-0}" ;;
          *"patch_window.sh status"*)
            if [[ -f "$STUB_STATE/rebooted" ]]; then
              STUB_REBOOT_REQUIRED=no
            fi
            eval "cat <<EOF
STATUS_OK_PLACEHOLDER
EOF" ;;
          *verify_egress.sh*) exit "${STUB_VERIFY_RC:-0}" ;;
          *"systemctl is-active --quiet http-collector"*) exit "${STUB_HTTP_COLLECTOR_RC:-0}" ;;
          *"systemctl is-active"*) exit 0 ;;
          *"systemctl reboot"*)
            [[ "${STUB_REBOOT_NOOP:-0}" == "1" ]] || touch "$STUB_STATE/rebooted"
            exit 255 ;;
          *boot_id*)
            if [[ -f "$STUB_STATE/rebooted" ]]; then echo "boot-b"; else echo "boot-a"; fi ;;
          true) exit 0 ;;
          *) exit 0 ;;
        esac
    """.replace("STATUS_OK_PLACEHOLDER", STATUS_OK.rstrip("\n")),
    "scp": r"""
        #!/usr/bin/env bash
        echo "scp $*" >> "$STUB_LOG"
    """,
}


class PatchSensorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.bin = self.tmp / "bin"
        self.state = self.tmp / "state"
        self.bin.mkdir()
        self.state.mkdir()
        for name, body in STUBS.items():
            path = self.bin / name
            path.write_text(textwrap.dedent(body).lstrip())
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.key = self.tmp / "operator_key"
        self.key.write_text("not a real key\n")
        self.log = self.tmp / "calls.log"
        self.log.touch()

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "STUB_LOG": str(self.log),
            "STUB_STATE": str(self.state),
            "PATCH_SENSOR_TF_DIR": str(self.tmp),
            "PATCH_SENSOR_SLEEP_SECONDS": "0.05",
            "PATCH_SENSOR_REBOOT_WAIT_SECONDS": "1",
        }
        env.update(extra)
        return env

    def run_script(self, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), "--key", str(self.key), "--yes", *args],
            env=self.env(**extra),
            capture_output=True,
            text=True,
            timeout=60,
        )

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()

    def index(self, needle: str) -> int:
        return next(i for i, c in enumerate(self.calls()) if needle in c)

    def applies(self) -> list[str]:
        return [c for c in self.calls() if c.startswith("terraform apply")]

    # --- happy path -----------------------------------------------------------

    def test_happy_path_order_and_targeted_applies(self) -> None:
        proc = self.run_script()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        applies = self.applies()
        self.assertEqual(len(applies), 2)
        for apply in applies:
            self.assertIn("-target=aws_vpc_security_group_egress_rule.patch_http", apply)
        self.assertIn('patch_egress_cidrs=["104.20.28.246/32","172.66.152.176/32"]', applies[0])
        self.assertIn("patch_egress_cidrs=[]", applies[1])
        self.assertLess(self.index("ec2 create-snapshot"), self.index("terraform apply"))
        self.assertLess(self.index("patch_window.sh resolve"), self.index("terraform apply"))
        self.assertLess(self.index("patch_window.sh run"), self.index("patch_egress_cidrs=[]"))
        self.assertLess(self.index("patch_egress_cidrs=[]"), self.index("patch_window.sh status"))
        self.assertIn("DeleteAfter", next(c for c in self.calls() if "create-snapshot" in c))
        self.assertFalse(any("delete-snapshot" in c for c in self.calls()))
        self.assertFalse(any("systemctl reboot" in c for c in self.calls()))
        self.assertIn("done: patched, egress closed", proc.stdout)

    # --- close always runs ------------------------------------------------------

    def test_patch_failure_still_closes_and_fails(self) -> None:
        proc = self.run_script(STUB_RUN_RC="1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(len(self.applies()), 2)
        self.assertIn("patch_egress_cidrs=[]", self.applies()[1])
        self.assertIn("patch window failed (egress closed and verified)", proc.stderr)

    def test_failed_or_declined_open_still_closes(self) -> None:
        proc = self.run_script(STUB_TF_OPEN_RC="1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(len(self.applies()), 2)
        self.assertIn("patch_egress_cidrs=[]", self.applies()[1])
        self.assertFalse(any("patch_window.sh run" in c for c in self.calls()))

    def test_close_failure_is_loud_and_exit_3(self) -> None:
        proc = self.run_script(STUB_TF_CLOSE_RC="1")
        self.assertEqual(proc.returncode, 3)
        self.assertIn("CLOSE FAILED", proc.stderr)
        self.assertFalse(any("patch_window.sh status" in c for c in self.calls()))

    def test_sigterm_during_patch_still_closes(self) -> None:
        proc = subprocess.Popen(
            ["bash", str(SCRIPT), "--key", str(self.key), "--yes"],
            env=self.env(STUB_RUN_SLEEP="3"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not any(
            "patch_window.sh run" in c for c in self.calls()
        ):
            time.sleep(0.05)
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(any("patch_egress_cidrs=[]" in c for c in self.applies()))

    # --- preflight and validation stop before anything opens -----------------

    def test_drift_aborts_before_snapshot_or_apply(self) -> None:
        proc = self.run_script(STUB_TF_PREFLIGHT_RC="2")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("pending changes", proc.stderr)
        self.assertEqual(self.applies(), [])
        self.assertFalse(any("create-snapshot" in c for c in self.calls()))

    def test_non_empty_tfvars_aborts(self) -> None:
        proc = self.run_script(STUB_TF_PATCH_LEN="2")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("patch_egress_cidrs must be []", proc.stderr)
        self.assertEqual(self.applies(), [])

    def test_unexpected_resolve_output_aborts_before_open(self) -> None:
        for bad in ("0.0.0.0/0\\n", "104.20.28.0/24\\n", "\\n", "evil; rm -rf /\\n"):
            self.log.write_text("")
            (self.state / "plans").unlink(missing_ok=True)
            proc = self.run_script(STUB_RESOLVE=bad)
            self.assertNotEqual(proc.returncode, 0, bad)
            self.assertEqual(self.applies(), [], bad)

    def test_missing_key_is_rejected(self) -> None:
        proc = subprocess.run(
            ["bash", str(SCRIPT), "--yes"], env=self.env(), capture_output=True, text=True, timeout=30
        )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(self.calls(), [])

    # --- verification, reboot, snapshots --------------------------------------

    def test_host_verification_failure_after_close(self) -> None:
        proc = self.run_script(STUB_TEMP_RULE="PRESENT")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("temporary rule still present", proc.stderr)
        self.assertIn("patch_egress_cidrs=[]", self.applies()[-1])

    def test_verify_plan_not_clean_fails(self) -> None:
        proc = self.run_script(STUB_TF_VERIFY_RC="2")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("terraform plan is not clean after closing", proc.stderr)

    def test_reboot_when_required_then_reverify(self) -> None:
        proc = self.run_script(STUB_REBOOT_REQUIRED="yes")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        calls = self.calls()
        reboot = self.index("systemctl reboot")
        self.assertGreater(reboot, self.index("patch_egress_cidrs=[]"))
        self.assertTrue(any("patch_window.sh status" in c for c in calls[reboot:]))

    def test_reboot_that_did_not_happen_is_detected(self) -> None:
        proc = self.run_script(STUB_REBOOT_REQUIRED="yes", STUB_REBOOT_NOOP="1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("did not complete a reboot", proc.stderr)

    def test_each_service_is_checked_separately(self) -> None:
        proc = self.run_script(STUB_HTTP_COLLECTOR_RC="3")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("sensor service http-collector is not active", proc.stderr)
        units = [c for c in self.calls() if "systemctl is-active" in c]
        self.assertTrue(all(len(c.split("--quiet ")[1].split()) == 1 for c in units))

    def test_reboot_never_skips_reboot(self) -> None:
        proc = self.run_script("--reboot", "never", STUB_REBOOT_REQUIRED="yes")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(any("systemctl reboot" in c for c in self.calls()))
        self.assertIn("reboot manually soon", proc.stdout)

    def test_expired_snapshots_listed_but_not_deleted_by_default(self) -> None:
        proc = self.run_script(STUB_EXPIRED="snap-0old1 snap-0old2")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(any("delete-snapshot" in c for c in self.calls()))
        self.assertIn("snap-0old1 snap-0old2", proc.stdout)

    def test_expired_snapshots_deleted_with_flag(self) -> None:
        proc = self.run_script("--delete-expired-snapshots", STUB_EXPIRED="snap-0old1 snap-0old2")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        deletes = [c for c in self.calls() if "delete-snapshot" in c]
        self.assertEqual(len(deletes), 2)
        self.assertFalse(any("snap-0aaa111" in c for c in deletes))


if __name__ == "__main__":
    unittest.main()
