"""
HTTP Client for web app and webserver checks.

Uses requests library for:
- Header inspection
- TLS/cipher analysis
- Cookie flag checking
- Endpoint discovery
"""


from typing import Optional
import requests

from sec_audit.results import ScanResult


class HttpScanner:
    """Simple HTTP scanner wrapper around requests."""

    def __init__(self, base_url: str, timeout: int = 5, scan_result: Optional[ScanResult] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.scan_result = scan_result


    def get_root(self) -> requests.Response:
        """
        Perform a GET request to the root URL.

        Returns:
            requests.Response object with text, status_code, headers, cookies, etc.
        """
        response = self.session.get(
            self.base_url,
            timeout=self.timeout,
            allow_redirects=True,
        )
        
        # Version fingerprinting (optional, safe no-op if scan_result is None)
        if self.scan_result is not None:
            server_header = response.headers.get("Server", "")
            if server_header:
                self.scan_result._webserver_version = server_header

            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                # Simple heuristic: record as app version hint
                self.scan_result._app_version = powered_by

        return response

    
    def head_root(self) -> requests.Response:
        """
        Perform a HEAD request to the root URL.

        Returns:
            requests.Response object with headers and status_code.
        """
        response = self.session.head(
            self.base_url,
            timeout=self.timeout,
            allow_redirects=True,
        )
        return response
    