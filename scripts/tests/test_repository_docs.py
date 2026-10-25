#!/usr/bin/env python3
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return (ROOT / path).read_text()


class RepositoryDocsTest(unittest.TestCase):
    def test_add_server_row_documents_wizard_and_bootstrap_arguments(self):
        row = next(line for line in read("README.md").splitlines()
                   if line.startswith("| Add a new server |"))
        self.assertIn("`/admin/servers/new` wizard", row)
        self.assertIn("`vpnctl bootstrap <id> --address <ip>`", row)
        self.assertIn("`--root-password` or `VPNCTL_ROOT_PW`", row)
        self.assertIn("`vpnctl deploy <id>`", row)
        self.assertNotIn("quick-add", row)
        self.assertNotIn("<password>", row)

    def test_readme_build_provenance_requires_compile_time_environment(self):
        readme = read("README.md")
        self.assertIn("only when `VPNCTL_BUILD_SHA` is set at compile time", readme)
        self.assertIn("`+unknown` when `VPNCTL_BUILD_SHA` is unset, even inside a Git checkout", readme)
        self.assertIn("`scripts/deploy.sh` exports", readme)
        self.assertNotIn("changes on **every** build from a checkout", readme)

    def test_backlog_closes_deploy_wait_item(self):
        backlog = read("BACKLOG.md")
        deploy = backlog.split("## Deploy All lock retry", 1)[1].split("\n## ", 1)[0]
        self.assertIn("**Status:** closed in code", deploy)
        self.assertIn("waiting up to 300 s", deploy)
        self.assertIn("polling every 500 ms", deploy)
        self.assertNotIn("Subscription base URL hard-coded", backlog)

    def test_traffic_docs_describe_cumulative_user_attribution(self):
        backlog = read("BACKLOG.md")
        traffic = backlog.split("## Cumulative per-user traffic attribution", 1)[1]
        self.assertIn("**Status:** closed in code", traffic)
        self.assertIn("SshStatsClient::cumulative_snapshot", traffic)
        self.assertIn("record_vpn_cumulative_stats", traffic)
        self.assertIn("docs/specs/traffic-accounting-v2.md", traffic)
        abuse = read("docs/specs/abuse-detection.md")
        self.assertIn("Cumulative V2Ray Stats supplies", abuse)
        self.assertIn("populated for attributed users and remains NULL for server-wide totals", abuse)
        self.assertNotIn("stays NULL until", abuse)

    def test_backup_bundle_policy_has_one_owner(self):
        contract = read("docs/specs/backup-restore.md")
        for requirement in [
            "nonempty, readable regular file, not a symlink (exit 13",
            "`zstd -3`",
            "Primary upload failure exits 11",
            "off-site delivery failure exits 14",
            "retention failure exits 15",
            "Delivery failures preserve the local archive",
            '`OFFSITE_HOST=""` disables',
        ]:
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, contract)
        commercial = read("docs/specs/commercial-operations.md")
        self.assertIn("backup-restore.md", commercial)
        self.assertNotIn("zstd -19", commercial)
        self.assertNotIn("Off-site push в скрипте best-effort", commercial)

if __name__ == "__main__":
    unittest.main()
