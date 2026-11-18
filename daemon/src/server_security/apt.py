"""Invoked over the pinned SSH channel. Only the JSON report reaches vpnctld."""

from functools import lru_cache

import fcntl
import json
import os
import re
import subprocess
import sys

NGINX = "/usr/sbin/nginx"


def os_release():
    with open("/etc/os-release", encoding="utf-8") as release:
        fields = dict(line.rstrip().split("=", 1) for line in release if "=" in line)
    return [fields.get(key, "").strip('"\'') for key in ("ID", "VERSION_CODENAME")]


def command(args, timeout=15, pass_fds=()):
    try:
        return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, errors="replace",
                              timeout=timeout, check=False, pass_fds=pass_fds)
    except (OSError, subprocess.TimeoutExpired):
        return None


def nginx_version(executable, pass_fds=()):
    result = command([executable, "-v"], pass_fds=pass_fds)
    if result and result.returncode == 0:
        match = re.search(r"\bnginx(?:-plus)?/[0-9][0-9.a-zA-Z+_-]*", result.stdout)
        if match:
            return match[0]
    return None


def nginx_status():
    if not os.path.isfile(NGINX):
        return None
    installed = nginx_version(NGINX)
    service = command(["systemctl", "show", "--property=MainPID", "--value", "nginx.service"])
    pid = service.stdout.strip() if service and service.returncode == 0 else ""
    running = None
    if pid.isdecimal() and int(pid) > 0:
        executable = f"/proc/{pid}/exe"
        try:
            with open(executable, "rb") as handle:
                fd = handle.fileno()
                pinned = f"/proc/self/fd/{fd}"
                if os.readlink(pinned) in (NGINX, NGINX + " (deleted)"):
                    running = nginx_version(pinned, pass_fds=(fd,))
        except OSError:
            pass
    config = command([NGINX, "-T"])
    http2 = None
    if config and config.returncode == 0:
        http2 = declares_http2(config.stdout)
    return {"installed": installed, "running": running, "http2": http2}


def declares_http2(config):
    # Remove comments and preserve quoted words without treating punctuation
    # inside a quote or escape as a directive boundary.
    pattern = r"""#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[;{}]|(?:\\.|[^\s#;{}'"\\])+"""
    words = []
    for match in re.finditer(pattern, config):
        token = match[0]
        if token.startswith("#"):
            continue
        if token == ";":
            if words == ["http2", "on"] or (words[:1] == ["listen"] and "http2" in words[1:]):
                return True
            words.clear()
        elif token in ("{", "}"):
            words.clear()
        else:
            words.append(token.strip("\"'"))
    return False


class ArchiveTrust:
    def __init__(self, apt_pkg, distro, release):
        self.origin = "Debian" if distro == "debian" else "Ubuntu"
        self.release = release
        self.keyring = f"/usr/share/keyrings/{distro}-archive-keyring.gpg"
        self.status_file = apt_pkg.config.find_file("Dir::State::status")
        self.sources = apt_pkg.SourceList()
        self.sources.read_main_list()
        self.apt_pkg = apt_pkg
        self.signed = lru_cache(maxsize=128)(self.signed_release)

    def signed_release(self, prefix):
        gpgv = ["gpgv", "--keyring", self.keyring]
        inline = f"{prefix}_InRelease"
        if os.path.isfile(inline):
            files = [inline]
        else:
            files = [f"{prefix}_Release.gpg", f"{prefix}_Release"]
        result = command(gpgv + files, timeout=5)
        return result is not None and result.returncode == 0

    def distribution_index(self, index):
        if index.origin != self.origin:
            return False
        codenames = {self.release, f"{self.release}-security", f"{self.release}-updates"}
        if index.codename not in codenames:
            return False
        # PackageFile.filename names the exact APT index for this version.
        # Verify that index's Release against the distro archive keyring.
        # Origin strings and SourceList.is_trusted alone permit trusted=yes.
        match = re.fullmatch(
            r"(.+_dists_[^_]+)_[^_]+_binary-[^_]+_Packages(?:\.[a-z0-9]+)?",
            index.filename,
        )
        entry = self.sources.find_index(index)
        return (match is not None and entry is not None and entry.is_trusted
                and self.signed(match[1]))

    def security_index(self, index):
        security = f"{self.release}-security"
        if self.origin == "Debian":
            declared = index.archive.endswith("-security") and index.codename == security
        else:
            declared = index.archive == security and index.codename == self.release
        return declared and self.distribution_index(index)

    def available(self):
        cache = self.apt_pkg.Cache()
        return any(self.security_index(index) for index in cache.file_list)

    def security_version(self, version):
        return any(self.security_index(index) for index, _ in version._cand.file_list)

    def safe_candidate(self, version):
        # APT can acquire a version from any index that publishes it.
        # Check every copy, excluding the local dpkg status record.
        return self.security_version(version) and all(
            index.filename == self.status_file or self.distribution_index(index)
            for index, _ in version._cand.file_list
        )


def dpkg_settled(cache, apt_pkg):
    settled = {apt_pkg.CURSTATE_NOT_INSTALLED, apt_pkg.CURSTATE_CONFIG_FILES,
               apt_pkg.CURSTATE_INSTALLED}
    return not cache.dpkg_journal_dirty and not cache.broken_count and all(
        pkg._pkg.current_state in settled for pkg in cache
    )


def held(pkg, apt_pkg):
    return pkg._pkg.selected_state == apt_pkg.SELSTATE_HOLD


def managed(pkg, kernels):
    name = pkg.name.split(":")[0]
    return any(name == kernel or name.startswith(f"{kernel}-") for kernel in kernels)


def pending(cache, apt_pkg, trust, kernels):
    packages = []
    for pkg in cache:
        if not pkg.is_installed or managed(pkg, kernels):
            continue
        installed = pkg.installed.version
        # VersionList iterates newest first, using APT's version ordering.
        fix = next((version for version in pkg.versions
                    if apt_pkg.version_compare(version.version, installed) > 0
                    and trust.security_version(version)), None)
        if fix is None:
            continue
        reason = None
        if held(pkg, apt_pkg):
            reason = "held"
        elif pkg.candidate is None or pkg.candidate.version != fix.version or not trust.safe_candidate(
                pkg.candidate):
            reason = "policy"
        packages.append({"name": pkg.fullname, "installed": installed,
                         "candidate": fix.version, "blocked": reason})
    return sorted(packages, key=lambda item: item["name"])


def apply(apt, apt_pkg, distro, release, kernels, requested):
    try:
        with apt_pkg.SystemLock():
            cache = apt.Cache(memonly=True)
            trust = ArchiveTrust(apt_pkg, distro, release)
            if not dpkg_settled(cache, apt_pkg) or not trust.available():
                return "blocked"
            for selected in requested:
                pkg = cache[selected["name"]]
                version = pkg.candidate
                if (managed(pkg, kernels) or held(pkg, apt_pkg)
                        or not pkg.is_installed or version is None
                        or pkg.installed.version != selected["installed"]
                        or version.version != selected["candidate"]
                        or apt_pkg.version_compare(version.version, pkg.installed.version) <= 0
                        or not trust.safe_candidate(version)):
                    return "changed"
                pkg.mark_install(auto_fix=False, auto_inst=False, from_user=False)
            planned = cache.get_changes()
            changes = {pkg.fullname for pkg in planned if pkg.marked_upgrade}
            if (cache.broken_count or changes != {item["name"] for item in requested}
                    or len(planned) != len(changes)):
                return "requires_other_changes"
            # Keep the frontend lock from the approval check through readback.
            # A failure from this point can leave some packages changed.
            try:
                if not cache.commit():
                    return "install_unverified"
                verified = apt.Cache(memonly=True)
                if not dpkg_settled(verified, apt_pkg) or not all(
                    verified[item["name"]].is_installed
                    and verified[item["name"]].installed.version == item["candidate"]
                    and verified[item["name"]]._pkg.current_state == apt_pkg.CURSTATE_INSTALLED
                    for item in requested
                ):
                    return "install_unverified"
            except (KeyError, OSError, SystemError, RuntimeError):
                return "install_unverified"
            return "verified"
    except KeyError:
        return "changed"
    except (OSError, SystemError, RuntimeError):
        return "blocked"


def refresh_indexes():
    try:
        result = subprocess.run(
            ["apt-get", "-q", "--error-on=any", "-o", "Acquire::Retries=0",
             "-o", "Acquire::http::Timeout=20", "-o", "Acquire::https::Timeout=20", "update"],
            stdin=subprocess.DEVNULL, timeout=100, check=False,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def report(apt, apt_pkg, distro, release, kernels):
    cache = apt.Cache(memonly=True)
    trust = ArchiveTrust(apt_pkg, distro, release)
    nginx = nginx_status()
    if not dpkg_settled(cache, apt_pkg):
        return {"state": "dpkg_unsettled", "nginx": nginx}
    if not trust.available():
        return {"state": "no_security_index", "nginx": nginx}
    return {"state": "checked", "packages": pending(cache, apt_pkg, trust, kernels),
            "nginx": nginx, "reboot_required": os.path.exists("/run/reboot-required")}


def run():
    distro, release = os_release()
    if distro not in {"debian", "ubuntu"} or not re.fullmatch(r"[a-z][a-z0-9-]*", release):
        return {"state": "unsupported"}
    try:
        import apt
        import apt_pkg
    except ImportError:
        return {"state": "missing_apt", "nginx": nginx_status()}
    with open("/run/lock/vpnctl-security.lock", "a", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"state": "busy"}
        request = json.loads(sys.argv[2])
        kernels = request["kernels"]
        if sys.argv[1] == "check":
            if not refresh_indexes():
                return {"state": "refresh_failed", "nginx": nginx_status()}
            return report(apt, apt_pkg, distro, release, kernels)
        os.environ["DEBIAN_FRONTEND"] = "noninteractive"
        apt_pkg.config.set("APT::Get::AllowUnauthenticated", "false")
        apt_pkg.config.set("Dpkg::Options::", "--force-confold")
        outcome = apply(apt, apt_pkg, distro, release, kernels, request["packages"])
        try:
            result = report(apt, apt_pkg, distro, release, kernels)
        except (OSError, SystemError, RuntimeError):
            result = {"state": "unavailable"}
        result["outcome"] = outcome
        return result


if __name__ == "__main__":
    # Package-manager output and configuration diagnostics can contain private
    # repository URLs and server settings. Keep both streams on the node.
    with os.fdopen(os.dup(sys.stdout.fileno()), "w", encoding="utf-8") as wire:
        with open(os.devnull, "w", encoding="utf-8") as sink:
            for stream in (sys.stdout, sys.stderr):
                os.dup2(sink.fileno(), stream.fileno())
            try:
                print(json.dumps(run()), file=wire)
            except (OSError, SystemError, RuntimeError, subprocess.TimeoutExpired):
                print('{"state":"unavailable"}', file=wire)
