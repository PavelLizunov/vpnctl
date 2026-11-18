import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


script = Path(__file__).resolve().parents[2] / "daemon/src/server_security/apt.py"
spec = importlib.util.spec_from_file_location("server_security_apt", script)
apt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apt)


class ServerSecurityTest(unittest.TestCase):
    def test_http2_scan_reads_inline_directives_and_ignores_comments_and_quotes(self):
        for config, expected in [
            ("server { listen 443 ssl http2; }", True),
            ("server { http2\n on; }", True),
            ('server { set $value "http2 on;"; # listen 443 http2;\n http2 off; }', False),
        ]:
            with self.subTest(config=config):
                self.assertEqual(apt.declares_http2(config), expected)

    def test_unpacked_package_is_unsettled_even_with_clean_journal(self):
        apt_pkg = SimpleNamespace(
            CURSTATE_NOT_INSTALLED=0, CURSTATE_CONFIG_FILES=5, CURSTATE_INSTALLED=6,
        )

        class Cache(list):
            dpkg_journal_dirty = False
            broken_count = 0

        for package_state, expected in [(0, True), (5, True), (6, True), (1, False)]:
            cache = Cache([SimpleNamespace(_pkg=SimpleNamespace(current_state=package_state))])
            with self.subTest(package_state=package_state):
                self.assertEqual(apt.dpkg_settled(cache, apt_pkg), expected)

    def test_apt_trusted_flag_and_release_labels_do_not_replace_distro_signature(self):
        config = Mock()
        config.find_file.return_value = "/var/lib/dpkg/status"
        sources = Mock()
        sources.find_index.return_value = SimpleNamespace(is_trusted=True)
        apt_pkg = SimpleNamespace(config=config, SourceList=lambda: sources)
        index = SimpleNamespace(
            filename="/var/lib/apt/lists/example.invalid_dists_bookworm-security_main_binary-amd64_Packages.lz4",
            origin="Debian", archive="oldstable-security", codename="bookworm-security",
        )
        with patch.object(apt.os.path, "isfile", return_value=True):
            for exit_status, expected in [(1, False), (0, True)]:
                with self.subTest(exit_status=exit_status), patch.object(
                    apt, "command", return_value=SimpleNamespace(returncode=exit_status)
                ) as gpgv:
                    trust = apt.ArchiveTrust(apt_pkg, "debian", "bookworm")
                    self.assertEqual(trust.security_index(index), expected)
                    gpgv.assert_called_once_with([
                        "gpgv", "--keyring", "/usr/share/keyrings/debian-archive-keyring.gpg",
                        "/var/lib/apt/lists/example.invalid_dists_bookworm-security_InRelease",
                    ], timeout=5)
