"""
test_guards.py — Guard clause correctness tests.

Proves that every check function returns Status.WARN immediately
when required credentials or paths are missing, WITHOUT crashing
or falling through into scanner connection code.

This is a direct proof that the missing-return bug has been fixed.
"""

import pytest
from unittest.mock import patch, MagicMock
from sec_audit.results import Status


# ─────────────────────────────────────────────────────────────────────────────
# Container check guards
# Each test calls the check with NO docker_host and asserts:
#   1. Status is WARN (not PASS, not FAIL, not an exception)
#   2. The Docker client was never instantiated (guard returned before connecting)
# ─────────────────────────────────────────────────────────────────────────────

class TestContainerCheckGuards:
    """All container checks must return WARN without connecting when docker_host is absent."""

    @patch("checks.container_checks.DockerScanner")
    def test_non_root_user_no_host(self, mock_docker_cls):
        from checks.container_checks import check_non_root_user
        result = check_non_root_user(docker_host=None)
        assert result.status == Status.WARN
        mock_docker_cls.assert_not_called()

    @patch("checks.container_checks.DockerScanner")
    def test_minimal_ports_no_host(self, mock_docker_cls):
        from checks.container_checks import check_minimal_ports
        result = check_minimal_ports(docker_host=None)
        assert result.status == Status.WARN
        mock_docker_cls.assert_not_called()

    @patch("checks.container_checks.DockerScanner")
    def test_health_checks_no_host(self, mock_docker_cls):
        from checks.container_checks import check_health_checks
        result = check_health_checks(docker_host=None)
        assert result.status == Status.WARN
        mock_docker_cls.assert_not_called()

    @patch("checks.container_checks.DockerScanner")
    def test_resource_limits_no_host(self, mock_docker_cls):
        from checks.container_checks import check_resource_limits
        result = check_resource_limits(docker_host=None)
        assert result.status == Status.WARN
        mock_docker_cls.assert_not_called()

    @patch("checks.container_checks.DockerScanner")
    def test_image_registry_no_host(self, mock_docker_cls):
        from checks.container_checks import check_image_registry
        result = check_image_registry(docker_host=None)
        assert result.status == Status.WARN
        mock_docker_cls.assert_not_called()

    @patch("checks.container_checks.DockerScanner")
    def test_no_secrets_no_host(self, mock_docker_cls):
        from checks.container_checks import check_no_secrets
        result = check_no_secrets(docker_host=None)
        assert result.status == Status.WARN
        mock_docker_cls.assert_not_called()

    @patch("checks.container_checks.DockerfileScanner")
    def test_dockerfile_user_no_path(self, mock_cls):
        from checks.container_checks import check_dockerfile_user
        result = check_dockerfile_user(path=None)
        assert result.status == Status.WARN
        mock_cls.assert_not_called()

    @patch("checks.container_checks.DockerfileScanner")
    def test_dockerfile_healthcheck_no_path(self, mock_cls):
        from checks.container_checks import check_dockerfile_healthcheck
        result = check_dockerfile_healthcheck(path=None)
        assert result.status == Status.WARN
        mock_cls.assert_not_called()

    @patch("checks.container_checks.DockerfileScanner")
    def test_dockerfile_best_practices_no_path(self, mock_cls):
        from checks.container_checks import check_dockerfile_best_practices
        result = check_dockerfile_best_practices(path=None)
        assert result.status == Status.WARN
        mock_cls.assert_not_called()

    @patch("checks.container_checks.ComposeScanner")
    def test_compose_resource_limits_no_path(self, mock_cls):
        from checks.container_checks import check_compose_resource_limits
        result = check_compose_resource_limits(path=None)
        assert result.status == Status.WARN
        mock_cls.assert_not_called()

    @patch("checks.container_checks.ComposeScanner")
    def test_compose_ports_no_path(self, mock_cls):
        from checks.container_checks import check_compose_ports
        result = check_compose_ports(path=None)
        assert result.status == Status.WARN
        mock_cls.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Host check guards
# Each test calls with no SSH params and asserts WARN without connecting.
# ─────────────────────────────────────────────────────────────────────────────

class TestHostCheckGuards:
    """All host checks must return WARN without connecting when SSH params are absent."""

    SSH_FUNCS = [
        "check_ssh_hardening",
        "check_firewall",
        "check_services",
        "check_auto_updates",
        "check_permissions",
        "check_logging",
        "check_gunicorn_user",
        "check_uwsgi_user",
        "check_mysql_user",
        "check_redis_user",
    ]

    @pytest.mark.parametrize("func_name", SSH_FUNCS)
    @patch("checks.host_checks.SSHScanner")
    def test_no_ssh_params_returns_warn(self, mock_ssh_cls, func_name):
        """Every host check returns WARN and never connects when SSH params missing."""
        import checks.host_checks as hc
        func = getattr(hc, func_name)
        # Call with no SSH params at all
        result = func(ssh_host=None, ssh_user=None, ssh_key=None, ssh_password=None)
        assert result.status == Status.WARN, (
            f"{func_name} returned {result.status} instead of WARN when SSH params missing"
        )
        mock_ssh_cls.assert_not_called()

    @pytest.mark.parametrize("func_name", SSH_FUNCS)
    @patch("checks.host_checks.SSHScanner")
    def test_partial_ssh_params_returns_warn(self, mock_ssh_cls, func_name):
        """Host checks return WARN even with partial params (host but no key/password)."""
        import checks.host_checks as hc
        func = getattr(hc, func_name)
        result = func(ssh_host="192.168.1.1", ssh_user="admin", ssh_key=None, ssh_password=None)
        assert result.status == Status.WARN
        mock_ssh_cls.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Webserver check guards
# nginx checks must return WARN without parsing when path is None.
# ─────────────────────────────────────────────────────────────────────────────

class TestWebserverCheckGuards:
    """Nginx config checks must return WARN without parsing when path is absent."""

    @patch("checks.webserver_checks.NginxConfigScanner")
    def test_nginx_hsts_no_path(self, mock_nginx_cls):
        from checks.webserver_checks import check_nginx_hsts_config
        result = check_nginx_hsts_config(path=None)
        assert result.status == Status.WARN
        mock_nginx_cls.assert_not_called()

    @patch("checks.webserver_checks.NginxConfigScanner")
    def test_nginx_csp_no_path(self, mock_nginx_cls):
        from checks.webserver_checks import check_nginx_csp_config
        result = check_nginx_csp_config(path=None)
        assert result.status == Status.WARN
        mock_nginx_cls.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Guard return type validation
# Ensures guards return proper CheckResult objects, not None or bare strings.
# ─────────────────────────────────────────────────────────────────────────────

class TestGuardReturnTypes:
    """Guard clause returns must be fully-formed CheckResult objects."""

    def test_container_guard_returns_check_result(self):
        from checks.container_checks import check_non_root_user
        from sec_audit.results import CheckResult
        with patch("checks.container_checks.DockerScanner"):
            result = check_non_root_user(docker_host=None)
        assert isinstance(result, CheckResult)
        assert result.id is not None
        assert result.layer is not None
        assert result.name is not None
        assert result.severity is not None
        assert result.details != ""

    def test_host_guard_returns_check_result(self):
        from checks.host_checks import check_ssh_hardening
        from sec_audit.results import CheckResult
        with patch("checks.host_checks.SSHScanner"):
            result = check_ssh_hardening(ssh_host=None, ssh_user=None)
        assert isinstance(result, CheckResult)
        assert result.id == "HOST-SSH-001"
        assert result.details != ""

    def test_webserver_guard_returns_check_result(self):
        from checks.webserver_checks import check_nginx_hsts_config
        from sec_audit.results import CheckResult
        with patch("checks.webserver_checks.NginxConfigScanner"):
            result = check_nginx_hsts_config(path=None)
        assert isinstance(result, CheckResult)
        assert result.id == "WS-CONF-HSTS"
