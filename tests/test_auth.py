"""Tests for WebBreaker authentication module."""

import base64

from core.auth import BasicAuth, FormAuth, SessionAuth, AuthResult, create_auth
from core.config import ScanConfig


# ── BasicAuth Tests ─────────────────────────────────────────────────

class TestBasicAuth:
    def test_basic_auth_header(self):
        """BasicAuth should build correct Authorization header."""
        auth = BasicAuth(username="admin", password="secret")
        expected = base64.b64encode(b"admin:secret").decode()
        assert auth.auth_header == f"Basic {expected}"

    def test_basic_auth_apply_to_config(self):
        """BasicAuth.apply_to_config should set auth_header on ScanConfig."""
        auth = BasicAuth(username="user", password="pass")
        config = ScanConfig(target="https://example.com", authorized=True)
        auth.apply_to_config(config)
        assert config.auth_header == auth.auth_header
        assert "Basic" in config.auth_header

    def test_basic_auth_special_chars(self):
        """BasicAuth should handle special characters in credentials."""
        auth = BasicAuth(username="user@domain", password="p@ss:w0rd!")
        expected = base64.b64encode(b"user@domain:p@ss:w0rd!").decode()
        assert auth.auth_header == f"Basic {expected}"

    def test_basic_auth_repr(self):
        """BasicAuth repr should show username."""
        auth = BasicAuth(username="admin", password="secret")
        assert "admin" in repr(auth)


# ── FormAuth Tests ──────────────────────────────────────────────────

class TestFormAuth:
    def test_form_auth_creation(self):
        """FormAuth should store all configuration."""
        auth = FormAuth(
            url="https://example.com/login",
            username="admin",
            password="secret",
            username_field="email",
            password_field="pwd",
            csrf_field="_token",
        )
        assert auth.url == "https://example.com/login"
        assert auth.username == "admin"
        assert auth.password == "secret"
        assert auth.username_field == "email"
        assert auth.password_field == "pwd"
        assert auth.csrf_field == "_token"
        assert auth.method == "POST"

    def test_form_auth_defaults(self):
        """FormAuth should have sensible defaults."""
        auth = FormAuth(url="https://example.com/login", username="u", password="p")
        assert auth.username_field == "username"
        assert auth.password_field == "password"
        assert auth.csrf_field is None
        assert auth.method == "POST"

    def test_extract_csrf_hidden_input(self):
        """FormAuth should extract CSRF from hidden input."""
        auth = FormAuth(url="http://test.com/login", username="u", password="p")
        html = '<form><input type="hidden" name="csrf_token" value="abc123"><input name="username"></form>'
        token = auth._extract_csrf(html, "csrf_token")
        assert token == "abc123"

    def test_extract_csrf_meta_tag(self):
        """FormAuth should extract CSRF from meta tag."""
        auth = FormAuth(url="http://test.com/login", username="u", password="p")
        html = '<meta name="csrf-token" content="xyz789">'
        token = auth._extract_csrf(html, "csrf-token")
        assert token == "xyz789"

    def test_extract_csrf_value_before_name(self):
        """FormAuth should extract CSRF when value comes before name."""
        auth = FormAuth(url="http://test.com/login", username="u", password="p")
        html = '<input type="hidden" value="token456" name="_token">'
        token = auth._extract_csrf(html, "_token")
        assert token == "token456"

    def test_extract_csrf_missing(self):
        """FormAuth should return None when CSRF token not found."""
        auth = FormAuth(url="http://test.com/login", username="u", password="p")
        html = '<form><input name="username"></form>'
        token = auth._extract_csrf(html, "csrf_token")
        assert token is None

    def test_check_success_pattern(self):
        """FormAuth should detect success via pattern."""
        auth = FormAuth(
            url="http://test.com/login",
            username="u", password="p",
            success_pattern=r"Welcome|Dashboard",
        )
        from unittest.mock import MagicMock
        resp = MagicMock()
        resp.text = "Welcome to the Dashboard"
        resp.status_code = 200
        resp.url = type("URL", (), {"path": "/dashboard"})()
        assert auth._check_success(resp) is True

    def test_check_failure_pattern(self):
        """FormAuth should detect success by failure pattern absence."""
        auth = FormAuth(
            url="http://test.com/login",
            username="u", password="p",
            failure_pattern=r"Invalid credentials|Login failed",
        )
        from unittest.mock import MagicMock
        resp = MagicMock()
        resp.text = "Welcome to your account"
        resp.status_code = 200
        resp.url = type("URL", (), {"path": "/dashboard"})()
        assert auth._check_success(resp) is True

    def test_check_failure_pattern_present(self):
        """FormAuth should detect failure when failure pattern is present."""
        auth = FormAuth(
            url="http://test.com/login",
            username="u", password="p",
            failure_pattern=r"Invalid credentials",
        )
        from unittest.mock import MagicMock
        resp = MagicMock()
        resp.text = "Invalid credentials. Please try again."
        resp.status_code = 200
        resp.url = type("URL", (), {"path": "/login"})()
        assert auth._check_success(resp) is False

    def test_check_success_redirect(self):
        """FormAuth should detect success via redirect away from login."""
        auth = FormAuth(url="http://test.com/login", username="u", password="p")
        from unittest.mock import MagicMock
        resp = MagicMock()
        resp.text = "Dashboard content"
        resp.status_code = 302
        resp.url = type("URL", (), {"path": "/dashboard"})()
        assert auth._check_success(resp) is True

    def test_check_success_no_password_field(self):
        """FormAuth should detect success when password field disappears."""
        auth = FormAuth(url="http://test.com/login", username="u", password="p")
        from unittest.mock import MagicMock
        resp = MagicMock()
        resp.text = "<html><body>Welcome back!</body></html>"
        resp.status_code = 200
        resp.url = type("URL", (), {"path": "/"})()
        assert auth._check_success(resp) is True

    def test_form_auth_repr(self):
        """FormAuth repr should show URL and username."""
        auth = FormAuth(url="https://example.com/login", username="admin", password="p")
        assert "example.com" in repr(auth)
        assert "admin" in repr(auth)


# ── SessionAuth Tests ───────────────────────────────────────────────

class TestSessionAuth:
    def test_session_auth_creation(self):
        """SessionAuth should extend FormAuth with retry config."""
        auth = SessionAuth(
            url="https://example.com/login",
            username="admin",
            password="secret",
            max_retries=5,
        )
        assert auth.max_retries == 5
        assert auth._retry_count == 0
        assert auth.url == "https://example.com/login"

    def test_session_auth_default_retries(self):
        """SessionAuth should default to 3 retries."""
        auth = SessionAuth(url="https://test.com/login", username="u", password="p")
        assert auth.max_retries == 3

    def test_session_auth_repr(self):
        """SessionAuth repr should include max_retries."""
        auth = SessionAuth(url="https://test.com/login", username="u", password="p", max_retries=5)
        assert "5" in repr(auth)

    def test_session_auth_is_form_auth(self):
        """SessionAuth should inherit from FormAuth."""
        auth = SessionAuth(url="https://test.com/login", username="u", password="p")
        assert isinstance(auth, FormAuth)


# ── AuthResult Tests ────────────────────────────────────────────────

class TestAuthResult:
    def test_successful_result(self):
        """AuthResult should be truthy when successful."""
        result = AuthResult(success=True, cookies={"session": "abc"}, message="OK")
        assert bool(result) is True
        assert result.cookies == {"session": "abc"}

    def test_failed_result(self):
        """AuthResult should be falsy when failed."""
        result = AuthResult(success=False, message="Bad credentials")
        assert bool(result) is False

    def test_default_values(self):
        """AuthResult should have sensible defaults."""
        result = AuthResult(success=False)
        assert result.cookies == {}
        assert result.token == ""
        assert result.message == ""


# ── create_auth Tests ───────────────────────────────────────────────

class TestCreateAuth:
    def test_create_basic_auth(self):
        """create_auth should create BasicAuth for auth_type='basic'."""
        config = ScanConfig(
            target="https://example.com",
            authorized=True,
            auth_type="basic",
            auth_username="admin",
            auth_password="secret",
        )
        auth = create_auth(config)
        assert isinstance(auth, BasicAuth)
        assert auth.username == "admin"

    def test_create_form_auth(self):
        """create_auth should create FormAuth for auth_type='form'."""
        config = ScanConfig(
            target="https://example.com",
            authorized=True,
            auth_type="form",
            auth_url="https://example.com/login",
            auth_username="admin",
            auth_password="secret",
        )
        auth = create_auth(config)
        assert isinstance(auth, FormAuth)
        assert auth.url == "https://example.com/login"

    def test_create_session_auth(self):
        """create_auth should create SessionAuth for auth_type='session'."""
        config = ScanConfig(
            target="https://example.com",
            authorized=True,
            auth_type="session",
            auth_url="https://example.com/login",
            auth_username="admin",
            auth_password="secret",
        )
        auth = create_auth(config)
        assert isinstance(auth, SessionAuth)
        assert auth.max_retries == 3

    def test_create_auth_none(self):
        """create_auth should return None when auth_type is not set."""
        config = ScanConfig(target="https://example.com", authorized=True)
        auth = create_auth(config)
        assert auth is None

    def test_create_basic_auth_missing_username(self):
        """create_auth should return None for basic auth without username."""
        config = ScanConfig(
            target="https://example.com",
            authorized=True,
            auth_type="basic",
            auth_password="secret",
        )
        auth = create_auth(config)
        assert auth is None

    def test_create_form_auth_missing_url(self):
        """create_auth should return None for form auth without URL."""
        config = ScanConfig(
            target="https://example.com",
            authorized=True,
            auth_type="form",
            auth_username="admin",
            auth_password="secret",
        )
        auth = create_auth(config)
        assert auth is None

    def test_create_auth_unknown_type(self):
        """create_auth should return None for unknown auth type."""
        config = ScanConfig(
            target="https://example.com",
            authorized=True,
            auth_type="oauth",
        )
        auth = create_auth(config)
        assert auth is None

    def test_create_form_auth_with_csrf(self):
        """create_auth should pass CSRF field to FormAuth."""
        config = ScanConfig(
            target="https://example.com",
            authorized=True,
            auth_type="form",
            auth_url="https://example.com/login",
            auth_username="admin",
            auth_password="secret",
            auth_csrf_field="csrf_token",
        )
        auth = create_auth(config)
        assert isinstance(auth, FormAuth)
        assert auth.csrf_field == "csrf_token"

    def test_create_session_auth_with_retries(self):
        """create_auth should pass max_retries to SessionAuth."""
        config = ScanConfig(
            target="https://example.com",
            authorized=True,
            auth_type="session",
            auth_url="https://example.com/login",
            auth_username="admin",
            auth_password="secret",
            auth_max_retries=5,
        )
        auth = create_auth(config)
        assert isinstance(auth, SessionAuth)
        assert auth.max_retries == 5


# ── ScanConfig Auth Fields Tests ────────────────────────────────────

class TestScanConfigAuthFields:
    def test_config_auth_fields_default(self):
        """ScanConfig auth fields should default to None/empty."""
        config = ScanConfig(target="https://example.com", authorized=True)
        assert config.auth_type is None
        assert config.auth_url is None
        assert config.auth_username is None
        assert config.auth_password is None
        assert config.auth_username_field == "username"
        assert config.auth_password_field == "password"
        assert config.auth_csrf_field is None
        assert config.auth_method == "POST"
        assert config.auth_max_retries == 3

    def test_config_auth_fields_set(self):
        """ScanConfig auth fields should accept values."""
        config = ScanConfig(
            target="https://example.com",
            authorized=True,
            auth_type="form",
            auth_url="https://example.com/login",
            auth_username="admin",
            auth_password="secret",
            auth_csrf_field="_token",
            auth_max_retries=5,
        )
        assert config.auth_type == "form"
        assert config.auth_url == "https://example.com/login"
        assert config.auth_max_retries == 5