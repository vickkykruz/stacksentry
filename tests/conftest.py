"""
Shared pytest fixtures for StackSentry test suite.

Provides reusable mocks for:
- HttpScanner (HTTP responses)
- DockerScanner (container runtime)
- SSHScanner (host commands)
- ScanResult (with pre-built check lists)
"""

import pytest
from unittest.mock import MagicMock, patch
from sec_audit.results import CheckResult, ScanResult, Status, Severity


# ── CheckResult factories ─────────────────────────────────────────────────────

def make_check(
    id: str = "APP-DEBUG-001",
    layer: str = "app",
    name: str = "Test check",
    status: Status = Status.PASS,
    severity: Severity = Severity.HIGH,
    details: str = "Test details",
) -> CheckResult:
    """Create a CheckResult with sensible defaults."""
    return CheckResult(
        id=id, layer=layer, name=name,
        status=status, severity=severity, details=details,
    )


def make_scan_result(checks: list = None) -> ScanResult:
    """Create a ScanResult with optional check list."""
    checks = checks or []
    return ScanResult(target="http://test.example.com", mode="quick", checks=checks)


# ── HTTP mock fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def mock_response_factory():
    """
    Returns a factory that builds mock HTTP responses.

    Usage:
        resp = mock_response_factory(
            status_code=200,
            headers={"Strict-Transport-Security": "max-age=31536000"},
            text="<html>...</html>",
            cookies={},
        )
    """
    def _factory(
        status_code: int = 200,
        headers: dict = None,
        text: str = "",
        cookies: dict = None,
    ):
        resp = MagicMock()
        resp.status_code = status_code
        resp.headers = headers or {}
        resp.text = text
        resp.cookies = cookies if cookies is not None else {}
        return resp
    return _factory


@pytest.fixture
def mock_http_scanner(mock_response_factory):
    """
    A mock HttpScanner whose get_root() returns a configurable response.
    Override `mock_http_scanner.get_root.return_value` per test.
    """
    scanner = MagicMock()
    scanner.base_url = "http://test.example.com"
    scanner.get_root.return_value = mock_response_factory()
    scanner.session = MagicMock()
    scanner.session.get.return_value = mock_response_factory()
    return scanner


# ── Docker mock fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def mock_container_factory():
    """
    Returns a factory that builds mock Docker container objects.

    Usage:
        container = mock_container_factory(user="appuser", ports={"80/tcp": [...]})
    """
    def _factory(
        user: str = "appuser",
        ports: dict = None,
        memory_limit: int = 536870912,
        cpu_limit: int = 50000,
        healthcheck: dict = None,
        image: str = "python:3.11-slim",
        env: list = None,
    ):
        container = MagicMock()
        container.attrs = {
            "Config": {
                "User": user,
                "Healthcheck": healthcheck or {"Test": ["CMD", "curl", "-f", "http://localhost/"]},
                "Env": env or ["PATH=/usr/local/bin"],
            },
            "HostConfig": {
                "PortBindings": ports or {"80/tcp": [{"HostPort": "8080"}]},
                "Memory": memory_limit,
                "CpuQuota": cpu_limit,
                "NanoCpus": 0,
            },
        }
        container.image.tags = [image]
        return container
    return _factory


@pytest.fixture
def mock_docker_scanner(mock_container_factory):
    """
    A mock DockerScanner pre-configured with a healthy container.
    Override attributes per test.
    """
    scanner = MagicMock()
    default_container = mock_container_factory()
    scanner.connect.return_value = MagicMock()
    scanner.get_target_container.return_value = default_container
    scanner.get_container_info.return_value = {
        "user": "appuser",
        "ports": {"80/tcp": [{"HostPort": "8080"}]},
        "memory_limit": 536870912,
        "cpu_limit": 50000,
        "healthcheck": {"Test": ["CMD", "curl", "-f", "http://localhost/"]},
        "image": "python:3.11-slim",
        "env": ["PATH=/usr/local/bin", "APP_ENV=production"],
    }
    return scanner


# ── SSH mock fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def mock_ssh_scanner():
    """
    A mock SSHScanner whose run_command() returns configurable output.
    Override `mock_ssh_scanner.run_command.return_value` per test.
    """
    scanner = MagicMock()
    scanner.connect.return_value = MagicMock()
    scanner.run_command.return_value = ("", 0)
    scanner.detect_os_version.return_value = "Ubuntu 22.04.3 LTS"
    return scanner


# ── Full scan result fixtures ─────────────────────────────────────────────────

@pytest.fixture
def all_pass_scan_result():
    """A ScanResult where every check passes — expected grade A."""
    checks = [
        make_check("APP-DEBUG-001",  "app",       "Debug mode disabled",       Status.PASS, Severity.HIGH),
        make_check("APP-COOKIE-001", "app",       "Secure session cookies",     Status.PASS, Severity.HIGH),
        make_check("APP-CSRF-001",   "app",       "CSRF protection enabled",    Status.PASS, Severity.MEDIUM),
        make_check("APP-ADMIN-001",  "app",       "No exposed admin endpoints", Status.PASS, Severity.MEDIUM),
        make_check("APP-RATE-001",   "app",       "Rate limiting configured",   Status.PASS, Severity.MEDIUM),
        make_check("APP-PASS-001",   "app",       "Strong password policy",     Status.PASS, Severity.LOW),
        make_check("WS-HSTS-001",    "webserver", "HSTS header enabled",        Status.PASS, Severity.HIGH),
        make_check("WS-SEC-001",     "webserver", "Security headers present",   Status.PASS, Severity.HIGH),
        make_check("WS-TLS-001",     "webserver", "TLS 1.2+ strong ciphers",    Status.PASS, Severity.HIGH),
        make_check("WS-SRV-001",     "webserver", "No server version disclosure",Status.PASS, Severity.MEDIUM),
        make_check("CONT-USER-001",  "container", "Non-root container user",    Status.PASS, Severity.HIGH),
        make_check("CONT-SEC-001",   "container", "No secrets in environment",  Status.PASS, Severity.HIGH),
        make_check("HOST-SSH-001",   "host",      "SSH hardening",              Status.PASS, Severity.HIGH),
        make_check("HOST-FW-001",    "host",      "Firewall enabled",           Status.PASS, Severity.HIGH),
    ]
    return make_scan_result(checks)


@pytest.fixture
def mixed_scan_result():
    """A ScanResult with a realistic mix of PASS/FAIL/WARN — expected grade C/D."""
    checks = [
        make_check("APP-DEBUG-001",  "app",       "Debug mode disabled",       Status.FAIL, Severity.HIGH,
                   "DEBUG=True detected. Set DEBUG=False in config."),
        make_check("APP-COOKIE-001", "app",       "Secure session cookies",    Status.WARN, Severity.HIGH,
                   "Cookies present but missing Secure flag."),
        make_check("APP-CSRF-001",   "app",       "CSRF protection enabled",   Status.PASS, Severity.MEDIUM),
        make_check("WS-HSTS-001",    "webserver", "HSTS header enabled",       Status.FAIL, Severity.HIGH,
                   "Strict-Transport-Security header is missing."),
        make_check("WS-SEC-001",     "webserver", "Security headers present",  Status.PASS, Severity.HIGH),
        make_check("WS-TLS-001",     "webserver", "TLS 1.2+ strong ciphers",   Status.WARN, Severity.HIGH,
                   "TLS details unavailable or cipher does not look modern."),
        make_check("CONT-USER-001",  "container", "Non-root container user",   Status.FAIL, Severity.HIGH,
                   "Container runs as root. Add USER 1000 to Dockerfile."),
        make_check("CONT-SEC-001",   "container", "No secrets in environment", Status.PASS, Severity.HIGH),
        make_check("HOST-SSH-001",   "host",      "SSH hardening",             Status.PASS, Severity.HIGH),
        make_check("HOST-FW-001",    "host",      "Firewall enabled",          Status.WARN, Severity.HIGH,
                   "Could not confirm active firewall."),
    ]
    return make_scan_result(checks)


@pytest.fixture
def all_fail_scan_result():
    """A ScanResult where every check fails — expected grade F."""
    checks = [
        make_check("APP-DEBUG-001",  "app",       "Debug mode disabled",       Status.FAIL, Severity.HIGH),
        make_check("APP-COOKIE-001", "app",       "Secure session cookies",    Status.FAIL, Severity.HIGH),
        make_check("WS-HSTS-001",    "webserver", "HSTS header enabled",       Status.FAIL, Severity.HIGH),
        make_check("WS-SEC-001",     "webserver", "Security headers present",  Status.FAIL, Severity.HIGH),
        make_check("CONT-USER-001",  "container", "Non-root container user",   Status.FAIL, Severity.HIGH),
        make_check("HOST-SSH-001",   "host",      "SSH hardening",             Status.FAIL, Severity.HIGH),
    ]
    return make_scan_result(checks)
