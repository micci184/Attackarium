import json
import unittest
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name("opencanary.conf.example")
SECRET_KEYS = {"password", "secret", "token", "api_key", "hmac", "private_key"}


def _keys(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            found.add(str(key).lower())
            found.update(_keys(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_keys(child))
    return found


class OpenCanaryConfigTests(unittest.TestCase):
    def test_audit_ignores_only_advisories_for_decoys_that_are_off(self) -> None:
        """An ignored Twisted advisory must stay irrelevant to the enabled decoys."""
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        workflow = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / "sensor-dependency-audit.yml"
        ).read_text(encoding="utf-8")
        # GHSA-8pqf-f4m5-798g: Twisted IMAP4 server ReDoS (no fixed release).
        if "GHSA-8pqf-f4m5-798g" in workflow:
            enabled = {key for key, value in config.items() if key.endswith(".enabled") and value}
            self.assertFalse(
                any(key.startswith("imap") for key in enabled),
                "remove the IMAP advisory ignore before enabling an IMAP decoy",
            )

    def test_enables_decoys_and_leaves_http_to_the_collector(self) -> None:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(config["device.node_id"], "sensor-replace-with-immutable-id")
        self.assertEqual(
            {
                "ssh": config["ssh.port"],
                "telnet": config["telnet.port"],
                "ftp": config["ftp.port"],
                "mysql": config["mysql.port"],
                "redis": config["redis.port"],
            },
            {"ssh": 22, "telnet": 23, "ftp": 21, "mysql": 3306, "redis": 6379},
        )
        for name in ("ssh", "telnet", "ftp", "mysql", "redis"):
            self.assertTrue(config[f"{name}.enabled"])
        for name in ("http", "https", "httpproxy"):
            self.assertFalse(config[f"{name}.enabled"])

        handler = config["logger"]["kwargs"]["handlers"]["jsonfile"]
        self.assertEqual(handler["class"], "logging.handlers.TimedRotatingFileHandler")
        self.assertTrue(str(handler["filename"]).endswith("opencanary.jsonl"))
        self.assertEqual(handler["backupCount"], 24)
        self.assertTrue(SECRET_KEYS.isdisjoint(_keys(config)))


if __name__ == "__main__":
    unittest.main()
