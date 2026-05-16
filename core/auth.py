"""Authentication support for WebBreaker scans.

Handles:
- Form-based login (POST username/password, extract session token)
- HTTP Basic authentication
- Session refresh (re-authenticate when session expires)

Usage:
    auth = FormAuth(url="https://target.com/login", username="user", password="pass")
    await auth.login(client)
    # client now has session cookies

    auth = BasicAuth(username="admin", password="secret")
    # client will send Authorization header

    auth = SessionAuth(url="https://target.com/login", username="user", password="pass")
    await auth.login(client)
    # client has session cookies + auto-refresh on 401/403
"""

import re
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console

console = Console()


@dataclass
class AuthResult:
    """Result of an authentication attempt."""
    success: bool
    cookies: dict = field(default_factory=dict)
    token: str = ""
    message: str = ""

    def __bool__(self) -> bool:
        return self.success


class BasicAuth:
    """HTTP Basic Authentication.

    Sends Authorization: Basic <encoded> header with every request.
    """

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.auth_header = self._build_header()

    def _build_header(self) -> str:
        """Build the Basic auth header value."""
        import base64
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    def apply_to_config(self, config) -> None:
        """Apply Basic auth to a ScanConfig."""
        config.auth_header = self.auth_header

    def __repr__(self) -> str:
        return f"BasicAuth(username={self.username!r})"


class FormAuth:
    """Form-based authentication.

    POSTs credentials to a login form and extracts session cookies/token
    from the response. Common for web applications with HTML login forms.
    """

    # Common CSRF token field names
    CSRF_FIELDS = [
        "csrf_token", "csrfmiddlewaretoken", "_token", "authenticity_token",
        "csrf", "_csrf_token", "__RequestVerificationToken", "nonce",
    ]

    # Common session cookie names
    SESSION_COOKIES = [
        "sessionid", "session", "PHPSESSID", "JSESSIONID", "connect.sid",
        "_ga", "laravel_session", "nova_session", "rack.session",
    ]

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        csrf_field: Optional[str] = None,
        method: str = "POST",
        success_pattern: Optional[str] = None,
        failure_pattern: Optional[str] = None,
    ):
        self.url = url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.csrf_field = csrf_field
        self.method = method.upper()
        self.success_pattern = success_pattern
        self.failure_pattern = failure_pattern

        # Populated after login
        self.cookies: dict = {}
        self.token: str = ""

    async def login(self, client) -> AuthResult:
        """Attempt form-based login and extract session cookies.

        Args:
            client: HttpClient instance to use for the login request.

        Returns:
            AuthResult with success status and extracted cookies/token.
        """

        # Step 1: Fetch the login page to extract CSRF token
        csrf_token = None
        if self.csrf_field:
            resp = await client.get(self.url)
            if resp and resp.status_code == 200:
                csrf_token = self._extract_csrf(resp.text, self.csrf_field)

        # Step 2: Build form data
        data = {
            self.username_field: self.username,
            self.password_field: self.password,
        }
        if csrf_token and self.csrf_field:
            data[self.csrf_field] = csrf_token

        # Step 3: Submit login form
        if self.method == "POST":
            resp = await client.post(
                self.url,
                data=data,
                follow_redirects=True,
            )
        else:
            resp = await client.request(
                self.method,
                self.url,
                params=data,
                follow_redirects=True,
            )

        if not resp:
            return AuthResult(
                success=False,
                message=f"No response from {self.url}",
            )

        # Step 4: Extract session cookies from response
        extracted_cookies = self._extract_cookies(resp)

        # Step 5: Determine success
        success = self._check_success(resp)

        if success:
            self.cookies = extracted_cookies
            # Merge into client config
            if client.config.cookies:
                client.config.cookies.update(extracted_cookies)
            else:
                client.config.cookies = extracted_cookies

            # Also update the client's default cookies for subsequent requests
            console.print(f"[green]✓[/] Authenticated as {self.username} (cookies: {list(extracted_cookies.keys())})")

            return AuthResult(
                success=True,
                cookies=extracted_cookies,
                message=f"Authenticated as {self.username}",
            )
        else:
            return AuthResult(
                success=False,
                cookies=extracted_cookies,
                message=f"Authentication failed for {self.username} (status: {resp.status_code})",
            )

    def _extract_csrf(self, html: str, field_name: str) -> Optional[str]:
        """Extract CSRF token from HTML form.

        Searches common patterns:
        - <input type="hidden" name="field" value="TOKEN">
        - <meta name="csrf-token" content="TOKEN">
        """
        # Pattern 1: hidden input field
        pattern = rf'<input[^>]+name=["\']?{re.escape(field_name)}["\']?[^>]+value=["\']?([^"\'>\s]+)["\']?'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)

        # Try value before name
        pattern2 = rf'<input[^>]+value=["\']?([^"\'>\s]+)["\']?[^>]+name=["\']?{re.escape(field_name)}["\']?'
        match = re.search(pattern2, html, re.IGNORECASE)
        if match:
            return match.group(1)

        # Pattern 2: meta tag
        meta_pattern = rf'<meta[^>]+name=["\']?{re.escape(field_name)}["\']?[^>]+content=["\']?([^"\'>\s]+)["\']?'
        match = re.search(meta_pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)

        # Pattern 3: Try value attribute in any order
        value_pattern = rf'name=["\']?{re.escape(field_name)}["\']?[^>]*value=["\']?([^"\'>\s]+)["\']?'
        match = re.search(value_pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)

        return None

    def _extract_cookies(self, response) -> dict:
        """Extract relevant session cookies from a response."""
        cookies = {}
        # httpx Response.cookies is a Cookies object
        for name in response.cookies:
            if name.lower() in {c.lower() for c in self.SESSION_COOKIES} or \
               any(name.lower().startswith(prefix.lower()) for prefix in ["session", "sid", "token"]):
                cookies[name] = response.cookies[name]

        # If no specific session cookies found, grab all cookies
        if not cookies and len(response.cookies) > 0:
            for name in response.cookies:
                cookies[name] = response.cookies[name]

        return cookies

    def _check_success(self, response) -> bool:
        """Check if login was successful based on response.

        Checks (in order):
        1. Success pattern match (if configured)
        2. Failure pattern absence (if configured)
        3. Redirect to non-login page (3xx to different path)
        4. 200 response without login form
        """
        # Explicit success pattern
        if self.success_pattern:
            return bool(re.search(self.success_pattern, response.text))

        # Explicit failure pattern — if NOT found, consider success
        if self.failure_pattern:
            return not bool(re.search(self.failure_pattern, response.text))

        # Heuristic: 2xx status code and page doesn't contain login form
        if response.status_code in (200, 201, 302, 303, 307):
            # If redirected away from login page, likely success
            if response.url.path != "/" and "login" not in str(response.url).lower():
                return True
            # If response doesn't contain password field, likely success
            if self.password_field not in response.text.lower():
                return True

        return False

    def __repr__(self) -> str:
        return f"FormAuth(url={self.url!r}, username={self.username!r})"


class SessionAuth(FormAuth):
    """Form-based authentication with automatic session refresh.

    Extends FormAuth with:
    - Automatic re-authentication when session expires (401/403 response)
    - Configurable refresh interval
    - Maximum retry count to prevent infinite loops
    """

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        csrf_field: Optional[str] = None,
        method: str = "POST",
        success_pattern: Optional[str] = None,
        failure_pattern: Optional[str] = None,
        max_retries: int = 3,
    ):
        super().__init__(
            url=url,
            username=username,
            password=password,
            username_field=username_field,
            password_field=password_field,
            csrf_field=csrf_field,
            method=method,
            success_pattern=success_pattern,
            failure_pattern=failure_pattern,
        )
        self.max_retries = max_retries
        self._retry_count = 0
        self._last_refresh: float = 0

    async def refresh_if_needed(self, client, response_status: int) -> bool:
        """Re-authenticate if session appears expired.

        Called when a response has 401 or 403 status. Returns True
        if re-authentication succeeded, False otherwise.

        Args:
            client: HttpClient instance.
            response_status: HTTP status code that triggered refresh.

        Returns:
            True if session was refreshed, False if max retries exceeded.
        """
        import time

        if response_status not in (401, 403):
            return True

        if self._retry_count >= self.max_retries:
            console.print(f"[red]✗[/] Session refresh failed: max retries ({self.max_retries}) exceeded")
            return False

        console.print(f"[yellow]⚠[/] Session expired (status {response_status}), re-authenticating...")
        self._retry_count += 1
        result = await self.login(client)

        if result.success:
            self._retry_count = 0  # Reset on success
            self._last_refresh = time.time()
            return True

        return False

    async def login(self, client) -> AuthResult:
        """Login and track refresh state."""
        result = await super().login(client)
        if result.success:
            self._retry_count = 0
        return result

    def __repr__(self) -> str:
        return f"SessionAuth(url={self.url!r}, username={self.username!r}, max_retries={self.max_retries})"


def create_auth(config) -> Optional[BasicAuth | FormAuth | SessionAuth]:
    """Create an auth handler from ScanConfig.

    Reads auth configuration from ScanConfig and returns the appropriate
    auth handler:
    - auth_type="basic" → BasicAuth
    - auth_type="form" → FormAuth
    - auth_type="session" → SessionAuth

    Returns None if no auth configuration is provided.
    """
    auth_type = getattr(config, "auth_type", None)
    if not auth_type:
        return None

    auth_type = auth_type.lower()

    if auth_type == "basic":
        username = getattr(config, "auth_username", "") or ""
        password = getattr(config, "auth_password", "") or ""
        if not username:
            console.print("[red]✗[/] Basic auth requires --auth-username")
            return None
        return BasicAuth(username=username, password=password)

    elif auth_type == "form":
        login_url = getattr(config, "auth_url", "") or ""
        username = getattr(config, "auth_username", "") or ""
        password = getattr(config, "auth_password", "") or ""
        if not login_url or not username:
            console.print("[red]✗[/] Form auth requires --auth-url and --auth-username")
            return None
        return FormAuth(
            url=login_url,
            username=username,
            password=password,
            username_field=getattr(config, "auth_username_field", "username") or "username",
            password_field=getattr(config, "auth_password_field", "password") or "password",
            csrf_field=getattr(config, "auth_csrf_field", None),
            method=getattr(config, "auth_method", "POST") or "POST",
            success_pattern=getattr(config, "auth_success_pattern", None),
            failure_pattern=getattr(config, "auth_failure_pattern", None),
        )

    elif auth_type == "session":
        login_url = getattr(config, "auth_url", "") or ""
        username = getattr(config, "auth_username", "") or ""
        password = getattr(config, "auth_password", "") or ""
        if not login_url or not username:
            console.print("[red]✗[/] Session auth requires --auth-url and --auth-username")
            return None
        return SessionAuth(
            url=login_url,
            username=username,
            password=password,
            username_field=getattr(config, "auth_username_field", "username") or "username",
            password_field=getattr(config, "auth_password_field", "password") or "password",
            csrf_field=getattr(config, "auth_csrf_field", None),
            method=getattr(config, "auth_method", "POST") or "POST",
            success_pattern=getattr(config, "auth_success_pattern", None),
            failure_pattern=getattr(config, "auth_failure_pattern", None),
            max_retries=getattr(config, "auth_max_retries", 3) or 3,
        )

    else:
        console.print(f"[red]✗[/] Unknown auth type: {auth_type}. Use: basic, form, session")
        return None