"""
Cisco Duo HMAC-SHA512 request signing utility.

This module provides functions for constructing canonical strings and computing
HMAC-SHA512 signatures for authenticating requests to the Duo Admin API.
"""

import base64
import hashlib
import hmac
import urllib.parse
from email.utils import formatdate


def build_canonical_string(date: str, method: str, host: str, path: str, params: dict) -> str:
    """
    Construct the canonical string for Duo API request signing.

    The canonical string is formed by joining 5 components with newline characters:
    1. date - RFC 2822 formatted date string
    2. method - HTTP method (uppercased)
    3. host - API hostname (lowercased)
    4. path - Request path
    5. params - Sorted, URL-encoded query/body parameters

    Args:
        date: RFC 2822 formatted date string.
        method: HTTP method (e.g., "GET", "POST").
        host: Duo API hostname.
        path: Request path (e.g., "/admin/v1/users").
        params: Dictionary of request parameters.

    Returns:
        The canonical string used as input to HMAC-SHA512 signing.
    """
    # Sort params alphabetically by key, URL-encode keys and values per RFC 3986
    if params:
        sorted_params = sorted(params.items())
        encoded_params = "&".join(
            "{}={}".format(
                urllib.parse.quote(str(k), safe=""),
                urllib.parse.quote(str(v), safe="")
            )
            for k, v in sorted_params
        )
    else:
        encoded_params = ""

    canonical = "\n".join([
        date,
        method.upper(),
        host.lower(),
        path,
        encoded_params
    ])

    return canonical


def sign_request(date: str, method: str, host: str, path: str, params: dict, secret_key: str) -> str:
    """
    Compute HMAC-SHA512 signature for a Duo API request.

    Args:
        date: RFC 2822 formatted date string.
        method: HTTP method.
        host: Duo API hostname.
        path: Request path.
        params: Dictionary of request parameters.
        secret_key: Duo API secret key for HMAC computation.

    Returns:
        Lowercase hex-encoded HMAC-SHA512 digest.

    Raises:
        ValueError: If secret_key is empty or None.
    """
    if not secret_key:
        raise ValueError("secret_key is required and cannot be empty or None")

    canonical_string = build_canonical_string(date, method, host, path, params)

    sig = hmac.new(
        secret_key.encode("utf-8"),
        canonical_string.encode("utf-8"),
        hashlib.sha512
    )

    return sig.hexdigest()


def build_authorization_header(integration_key: str, signature: str) -> str:
    """
    Construct the Authorization header value for Duo API requests.

    The header format is: "Basic base64(integration_key:signature)"

    Args:
        integration_key: Duo Admin API integration key.
        signature: Hex-encoded HMAC-SHA512 signature.

    Returns:
        The complete Authorization header value.
    """
    auth_string = "{}:{}".format(integration_key, signature)
    encoded = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
    return "Basic {}".format(encoded)


def get_auth_headers(method: str, host: str, path: str, params: dict, integration_key: str, secret_key: str) -> dict:
    """
    High-level helper that returns complete headers dict for a Duo API request.

    Generates the current date in RFC 2822 format, computes the HMAC-SHA512
    signature, and constructs the Authorization header.

    Args:
        method: HTTP method.
        host: Duo API hostname.
        path: Request path.
        params: Dictionary of request parameters.
        integration_key: Duo Admin API integration key.
        secret_key: Duo Admin API secret key.

    Returns:
        Dictionary with 'Authorization' and 'Date' headers.

    Raises:
        ValueError: If secret_key is empty or None.
    """
    if not secret_key:
        raise ValueError("secret_key is required and cannot be empty or None")

    # Generate current date in RFC 2822 format with GMT timezone
    date = formatdate(usegmt=True)

    signature = sign_request(date, method, host, path, params, secret_key)
    authorization = build_authorization_header(integration_key, signature)

    return {
        "Authorization": authorization,
        "Date": date
    }
