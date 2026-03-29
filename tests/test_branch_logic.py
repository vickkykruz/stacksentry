"""
test_branch_logic.py — Branch logic correctness tests.

Proves that the elif/else bug has been fixed:
FAIL must be returned when the check actually fails.
PASS must not overwrite FAIL.

Each test simulates a bad configuration, runs the check with mocked
scanners, and asserts the result is FAIL — not PASS.
"""

import pytest
from unittest.mock import patch, MagicMock, call
from sec_audit.results import Status


# ─────────────────────────────────────────────────────────────────────────────
# Container check branch logic
# ─────────────────────────────────────────────────────────────────────────────

class TestContainerBranchLogic:
    """Container checks must return FAIL when the scanner reports a bad configuration."""

    def _make_scanner(self, info_overrides: dict):
        """Build a mock DockerScanner with specified container info."""
        default_info = {
            "user": "appuser",
            "ports": {"80/tcp": [{"HostPort": "8080"}]},
            "memory_limit": 536870912,
            "cpu_limit": 50000,
            "healthcheck": {"Test": ["CMD", "curl", "-f", "http://localhost/"]},
            "image": "python:3.11-slim",
            "env": ["PATH=/usr/local/bin"],
        }
        default_info.update(info_overrides)
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        scanner.get_target_container.return_value = MagicMock()
        scanner.get_container_info.return_value = default_info
        return scanner

    @patch("checks.container_checks.DockerScanner")
    def test_root_user_returns_fail(self, mock_cls):
        """check_non_root_user must FAIL when container user is root."""
        from checks.container_checks import check_non_root_user
        mock_cls.return_value = self._make_scanner({"user": "root"})
        result = check_non_root_user(docker_host="unix:///var/run/docker.sock")
        assert result.status == Status.FAIL, (
            f"Expected FAIL for root user, got {result.status}. "
            "The elif bug may still be present."
        )

    @patch("checks.container_checks.DockerScanner")
    def test_empty_user_returns_fail(self, mock_cls):
        """check_non_root_user must FAIL when container user is empty string."""
        from checks.container_checks import check_non_root_user
        mock_cls.return_value = self._make_scanner({"user": ""})
        result = check_non_root_user(docker_host="unix:///var/run/docker.sock")
        assert result.status == Status.FAIL

    @patch("checks.container_checks.DockerScanner")
    def test_uid_zero_returns_fail(self, mock_cls):
        """check_non_root_user must FAIL when container user is UID 0."""
        from checks.container_checks import check_non_root_user
        mock_cls.return_value = self._make_scanner({"user": "0"})
        result = check_non_root_user(docker_host="unix:///var/run/docker.sock")
        assert result.status == Status.FAIL

    @patch("checks.container_checks.DockerScanner")
    def test_non_root_user_returns_pass(self, mock_cls):
        """check_non_root_user must PASS when container user is non-root."""
        from checks.container_checks import check_non_root_user
        mock_cls.return_value = self._make_scanner({"user": "appuser"})
        result = check_non_root_user(docker_host="unix:///var/run/docker.sock")
        assert result.status == Status.PASS

    @patch("checks.container_checks.DockerScanner")
    def test_secrets_in_env_returns_fail(self, mock_cls):
        """check_no_secrets must FAIL when env contains secret-like variable names."""
        from checks.container_checks import check_no_secrets
        mock_cls.return_value = self._make_scanner({
            "env": ["PATH=/usr/local/bin", "DB_PASSWORD=supersecret123", "API_KEY=abcdef"]
        })
        result = check_no_secrets(docker_host="unix:///var/run/docker.sock")
        assert result.status == Status.FAIL

    @patch("checks.container_checks.DockerScanner")
    def test_no_secrets_in_env_returns_pass(self, mock_cls):
        """check_no_secrets must PASS when env contains no secret-like names."""
        from checks.container_checks import check_no_secrets
        mock_cls.return_value = self._make_scanner({
            "env": ["PATH=/usr/local/bin", "APP_ENV=production", "PORT=8080"]
        })
        result = check_no_secrets(docker_host="unix:///var/run/docker.sock")
        assert result.status == Status.PASS

    @patch("checks.container_checks.DockerScanner")
    def test_no_healthcheck_returns_warn(self, mock_cls):
        """check_health_checks must WARN when no healthcheck is configured."""
        from checks.container_checks import check_health_checks
        mock_cls.return_value = self._make_scanner({"healthcheck": None})
        result = check_health_checks(docker_host="unix:///var/run/docker.sock")
        assert result.status == Status.WARN

    @patch("checks.container_checks.DockerScanner")
    def test_healthcheck_present_returns_pass(self, mock_cls):
        """check_health_checks must PASS when healthcheck is configured."""
        from checks.container_checks import check_health_checks
        mock_cls.return_value = self._make_scanner({
            "healthcheck": {"Test": ["CMD", "curl", "-f", "http://localhost/"]}
        })
        result = check_health_checks(docker_host="unix:///var/run/docker.sock")
        assert result.status == Status.PASS

    @patch("checks.container_checks.DockerScanner")
    def test_no_resource_limits_returns_warn(self, mock_cls):
        """check_resource_limits must WARN when no CPU or memory limit is set."""
        from checks.container_checks import check_resource_limits
        mock_cls.return_value = self._make_scanner({
            "cpu_limit": 0,
            "memory_limit": 0,
        })
        result = check_resource_limits(docker_host="unix:///var/run/docker.sock")
        assert result.status == Status.WARN

    @patch("checks.container_checks.DockerScanner")
    def test_resource_limits_present_returns_pass(self, mock_cls):
        """check_resource_limits must PASS when memory limit is set."""
        from checks.container_checks import check_resource_limits
        mock_cls.return_value = self._make_scanner({
            "cpu_limit": 0,
            "memory_limit": 536870912,
        })
        result = check_resource_limits(docker_host="unix:///var/run/docker.sock")
        assert result.status == Status.PASS


# ─────────────────────────────────────────────────────────────────────────────
# Host check branch logic
# ─────────────────────────────────────────────────────────────────────────────

class TestHostBranchLogic:
    """Host checks must return FAIL when SSH commands report bad configuration."""

    SSH_CREDS = {
        "ssh_host": "192.168.1.100",
        "ssh_user": "admin",
        "ssh_key": "/home/user/.ssh/id_rsa",
    }

    def _mock_ssh(self, command_output: str, exit_code: int = 0):
        scanner = MagicMock()
        scanner.connect.return_value = MagicMock()
        scanner.run_command.return_value = (command_output, exit_code)
        scanner.detect_os_version.return_value = "Ubuntu 22.04 LTS"
        return scanner

    @patch("checks.host_checks.SSHScanner")
    def test_ssh_permit_root_yes_returns_fail(self, mock_cls):
        """check_ssh_hardening must FAIL when PermitRootLogin is yes."""
        from checks.host_checks import check_ssh_hardening
        mock_cls.return_value = self._mock_ssh("PermitRootLogin yes")
        result = check_ssh_hardening(**self.SSH_CREDS)
        assert result.status == Status.FAIL, (
            f"Expected FAIL for PermitRootLogin yes, got {result.status}."
        )

    @patch("checks.host_checks.SSHScanner")
    def test_ssh_permit_root_no_returns_pass(self, mock_cls):
        """check_ssh_hardening must PASS when PermitRootLogin is no."""
        from checks.host_checks import check_ssh_hardening
        mock_cls.return_value = self._mock_ssh("PermitRootLogin no")
        result = check_ssh_hardening(**self.SSH_CREDS)
        assert result.status == Status.PASS

    @patch("checks.host_checks.SSHScanner")
    def test_firewall_inactive_returns_fail(self, mock_cls):
        """check_firewall must FAIL when ufw reports inactive."""
        from checks.host_checks import check_firewall
        mock_cls.return_value = self._mock_ssh("Status: inactive")
        result = check_firewall(**self.SSH_CREDS)
        assert result.status == Status.FAIL

    @patch("checks.host_checks.SSHScanner")
    def test_firewall_active_returns_pass(self, mock_cls):
        """check_firewall must PASS when ufw reports active."""
        from checks.host_checks import check_firewall
        mock_cls.return_value = self._mock_ssh("Status: active")
        result = check_firewall(**self.SSH_CREDS)
        assert result.status == Status.PASS

    @patch("checks.host_checks.SSHScanner")
    def test_auto_updates_enabled_returns_pass(self, mock_cls):
        """check_auto_updates must PASS when unattended-upgrades is enabled."""
        from checks.host_checks import check_auto_updates
        mock_cls.return_value = self._mock_ssh("enabled")
        result = check_auto_updates(**self.SSH_CREDS)
        assert result.status == Status.PASS

    @patch("checks.host_checks.SSHScanner")
    def test_auto_updates_disabled_returns_warn(self, mock_cls):
        """check_auto_updates must WARN when unattended-upgrades is disabled."""
        from checks.host_checks import check_auto_updates
        mock_cls.return_value = self._mock_ssh("disabled")
        result = check_auto_updates(**self.SSH_CREDS)
        assert result.status == Status.WARN

    @patch("checks.host_checks.SSHScanner")
    def test_gunicorn_running_as_root_returns_fail(self, mock_cls):
        """check_gunicorn_user must FAIL when gunicorn runs as root."""
        from checks.host_checks import check_gunicorn_user
        mock_cls.return_value = self._mock_ssh("root")
        result = check_gunicorn_user(**self.SSH_CREDS)
        assert result.status == Status.FAIL

    @patch("checks.host_checks.SSHScanner")
    def test_gunicorn_running_as_non_root_returns_pass(self, mock_cls):
        """check_gunicorn_user must PASS when gunicorn runs as non-root user."""
        from checks.host_checks import check_gunicorn_user
        mock_cls.return_value = self._mock_ssh("webuser")
        result = check_gunicorn_user(**self.SSH_CREDS)
        assert result.status == Status.PASS

    @patch("checks.host_checks.SSHScanner")
    def test_world_writable_ssh_files_returns_warn(self, mock_cls):
        """check_permissions must WARN when world-writable SSH files are found."""
        from checks.host_checks import check_permissions
        mock_cls.return_value = self._mock_ssh("3")  # 3 world-writable files
        result = check_permissions(**self.SSH_CREDS)
        assert result.status == Status.WARN

    @patch("checks.host_checks.SSHScanner")
    def test_no_world_writable_ssh_files_returns_pass(self, mock_cls):
        """check_permissions must PASS when no world-writable SSH files exist."""
        from checks.host_checks import check_permissions
        mock_cls.return_value = self._mock_ssh("0")
        result = check_permissions(**self.SSH_CREDS)
        assert result.status == Status.PASS


# ─────────────────────────────────────────────────────────────────────────────
# App check branch logic
# ─────────────────────────────────────────────────────────────────────────────

class TestAppBranchLogic:
    """App layer checks must return correct status based on HTTP response content."""

    def _mock_scanner(self, text="", headers=None, cookies=None, status_code=200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.headers = headers or {}
        resp.text = text
        resp.cookies = cookies or {}
        scanner = MagicMock()
        scanner.base_url = "http://test.example.com"
        scanner.get_root.return_value = resp
        scanner.session = MagicMock()
        scanner.session.get.return_value = resp
        return scanner

    def test_debug_marker_in_body_returns_fail(self):
        """check_debug_mode must FAIL when debug traceback is in the response body."""
        from checks.app_checks import check_debug_mode
        scanner = self._mock_scanner(text="Traceback (most recent call last): ...")
        result = check_debug_mode(scanner)
        assert result.status == Status.FAIL

    def test_no_debug_marker_returns_pass(self):
        """check_debug_mode must PASS when no debug markers are in the response body."""
        from checks.app_checks import check_debug_mode
        scanner = self._mock_scanner(text="<html><body>Welcome</body></html>")
        result = check_debug_mode(scanner)
        assert result.status == Status.PASS

    def test_hsts_missing_returns_fail(self):
        """check_hsts_header must FAIL when HSTS header is absent."""
        from checks.webserver_checks import check_hsts_header
        scanner = self._mock_scanner(headers={})
        result = check_hsts_header(scanner)
        assert result.status == Status.FAIL

    def test_hsts_strong_returns_pass(self):
        """check_hsts_header must PASS when HSTS has strong max-age."""
        from checks.webserver_checks import check_hsts_header
        scanner = self._mock_scanner(
            headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
        )
        result = check_hsts_header(scanner)
        assert result.status == Status.PASS

    def test_admin_endpoint_exposed_returns_fail(self):
        """check_admin_endpoints must FAIL when /admin returns 200."""
        from checks.app_checks import check_admin_endpoints
        exposed_resp = MagicMock()
        exposed_resp.status_code = 200
        not_found_resp = MagicMock()
        not_found_resp.status_code = 404
        scanner = MagicMock()
        scanner.base_url = "http://test.example.com"
        scanner.session = MagicMock()
        scanner.session.get.side_effect = [
            exposed_resp,   # /admin → 200 (exposed)
            not_found_resp, # /debug → 404
            not_found_resp, # /test → 404
            not_found_resp, # /wp-admin → 404
        ]
        result = check_admin_endpoints(scanner)
        assert result.status == Status.FAIL

    def test_no_admin_endpoints_exposed_returns_pass(self):
        """check_admin_endpoints must PASS when no admin paths return 200."""
        from checks.app_checks import check_admin_endpoints
        not_found_resp = MagicMock()
        not_found_resp.status_code = 404
        scanner = MagicMock()
        scanner.base_url = "http://test.example.com"
        scanner.session = MagicMock()
        scanner.session.get.return_value = not_found_resp
        result = check_admin_endpoints(scanner)
        assert result.status == Status.PASS
