#!/usr/bin/env python3
"""
Get a Reddit OAuth2 refresh token via the Authorization Code flow.

- Opens the browser to authorize
- Runs a tiny localhost HTTP server to capture the redirect
- Exchanges the code for tokens
- (Optionally) saves the refresh token and creds to .env

Supports both "script" apps (client_secret required) and
"installed" apps with PKCE (no client_secret).

Requirements: requests, python-dotenv
"""

import argparse
import http.server
import socket
import socketserver
import threading
import webbrowser
import urllib.parse as urlparse
import requests
import os
import secrets
import time
from dotenv import set_key, load_dotenv

# ---- Config -----------------------------------------------------------------

AUTH_URL = "https://www.reddit.com/api/v1/authorize"
TOKEN_URL = "https://www.reddit.com/api/v1/access_token"

# ---- Utilities ---------------------------------------------------------------

def _now_ms():
    return int(time.time() * 1000)


def _mask(val: str, keep=4):
    if not val:
        return val
    if len(val) <= keep * 2:
        return "*" * len(val)
    return f"{val[:keep]}…{val[-keep:]}"


def _random_state():
    return secrets.token_urlsafe(16)


def _maybe_open_browser(url):
    print("\nOpening browser for authorization. If it doesn't open, visit this URL manually:\n")
    print(url, "\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass

# ---- Tiny HTTP server to catch the redirect ---------------------------------

class CodeHandler(http.server.BaseHTTPRequestHandler):
    server_version = "GetRefreshToken/1.0"

    def do_GET(self):
        parsed = urlparse.urlparse(self.path)
        qs = urlparse.parse_qs(parsed.query)
        # Persist everything on the server object so the caller can read it
        self.server.last_params = {k: v[0] for k, v in qs.items()}

        # Simple result page
        if "error" in qs:
            status = 400
            title = "Authorization failed"
            detail = f"Reddit returned error: {qs['error'][0]}"
        elif "code" in qs and "state" in qs:
            status = 200
            title = "Authorization complete"
            detail = "You can return to the app/terminal."
        else:
            status = 400
            title = "Invalid redirect"
            detail = "Missing required query parameters."

        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            f"""<!doctype html>
<html><body style="font-family: system-ui, -apple-system, Segoe UI, sans-serif">
<h2>{title}</h2>
<p>{detail}</p>
</body></html>""".encode("utf-8")
        )

    def log_message(self, *args, **kwargs):
        # Silence default logging
        return


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def run_local_server(expected_state, port=8080, timeout=300):
    """
    Run a small HTTP server until we get a redirect with either:
      - ?code=...&state=...
      - or ?error=...

    Returns a dict of query params.
    Raises TimeoutError if nothing arrives in time.
    """
    params_holder = {"params": None}
    deadline = time.time() + timeout

    with ThreadingTCPServer(("127.0.0.1", port), CodeHandler) as httpd:
        httpd.timeout = 1.0
        httpd.last_params = None

        def serve():
            while time.time() < deadline and httpd.last_params is None:
                httpd.handle_request()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        t.join(timeout)
        # Ensure we close the socket
        try:
            httpd.server_close()
        except Exception:
            pass

        if httpd.last_params is None:
            raise TimeoutError(f"No redirect received within {timeout} seconds")

        # CSRF protection: verify state matches
        if "state" in httpd.last_params and httpd.last_params["state"] != expected_state:
            raise ValueError("State mismatch. Aborting for safety.")

        return httpd.last_params

# ---- OAuth exchange ----------------------------------------------------------

def exchange_code_for_token(
    client_id,
    client_secret,
    code,
    user_agent,
    redirect_uri,
    use_pkce=False,
    code_verifier=None,
):
    """
    Exchange the authorization code for tokens.
    - Script apps: client_secret required (use_pkce=False).
    - Installed apps with PKCE: set use_pkce=True (no client_secret).
    """
    headers = {"User-Agent": user_agent}
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }

    auth = None
    if use_pkce:
        if not code_verifier:
            raise ValueError("PKCE enabled but code_verifier missing")
        data["code_verifier"] = code_verifier
        # No client_secret for installed apps; Reddit expects client_id in HTTP Basic with empty password
        auth = (client_id, "")
    else:
        # Script apps: client_id + client_secret via HTTP Basic
        auth = (client_id, client_secret or "")

    resp = requests.post(TOKEN_URL, auth=auth, data=data, headers=headers, timeout=30)
    # If Reddit returns 401/400, include the body for clarity
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        raise requests.HTTPError(f"{e} :: {resp.text}") from None
    return resp.json()

# ---- Main --------------------------------------------------------------------

def main():
    # Load .env (if present) BEFORE argparse so flags can override
    load_dotenv()

    parser = argparse.ArgumentParser(description="Fetch a Reddit OAuth2 refresh token.")
    parser.add_argument("--client-id", help="Reddit client id (or .env REDDIT_CLIENT_ID)")
    parser.add_argument("--client-secret", help="Reddit client secret (or .env REDDIT_CLIENT_SECRET). Leave empty for PKCE installed apps.")
    parser.add_argument("--user-agent", help="User-Agent header (or .env REDDIT_USER_AGENT)")
    parser.add_argument("--port", type=int, default=int(os.getenv("REDIRECT_PORT") or 8080), help="Local port for redirect")
    parser.add_argument("--scopes", default=os.getenv("REDDIT_SCOPES") or "read", help='Space- or comma-separated scopes, e.g. "read identity history"')
    parser.add_argument("--duration", choices=["temporary", "permanent"], default=os.getenv("REDDIT_DURATION") or "permanent", help="Token duration")
    parser.add_argument("--save", action="store_true", help="Save refresh_token and creds to .env")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open the browser")
    parser.add_argument("--pkce", action="store_true", help="Use PKCE (installed app). Leave client_secret empty.")
    args = parser.parse_args()

    client_id = os.getenv("REDDIT_CLIENT_ID") or args.client_id
    client_secret = os.getenv("REDDIT_CLIENT_SECRET") if args.client_secret is None else args.client_secret
    user_agent = os.getenv("REDDIT_USER_AGENT") or args.user_agent
    port = args.port

    if not client_id or not user_agent:
        print("Missing credentials. Provide REDDIT_CLIENT_ID and REDDIT_USER_AGENT (and REDDIT_CLIENT_SECRET for script apps) in .env or via CLI flags.")
        parser.print_help()
        raise SystemExit(2)

    if not args.pkce and client_secret is None:
        print("Note: you didn't pass --pkce and no client secret was given. If you're using a script app, provide --client-secret. If you're using an installed app, pass --pkce.")
        parser.print_help()
        raise SystemExit(2)

    redirect_uri = f"http://127.0.0.1:{port}"

    # Build scopes: accept comma or space separated
    scope_list = [s for chunk in args.scopes.split(",") for s in chunk.strip().split() if s.strip()]
    scope_str = " ".join(sorted(set(scope_list))) or "read"

    # CSRF protection
    state = _random_state()

    # Optional PKCE
    code_verifier = code_challenge = None
    code_challenge_method = None
    if args.pkce:
        # Generate high-entropy code_verifier (43-128 chars allowed)
        code_verifier = secrets.token_urlsafe(64)
        # S256 challenge
        import hashlib, base64
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        code_challenge_method = "S256"

    # Build auth URL safely
    q = {
        "client_id": client_id,
        "response_type": "code",
        "state": state,
        "redirect_uri": redirect_uri,
        "duration": args.duration,
        "scope": scope_str,
    }
    if args.pkce:
        q["code_challenge"] = code_challenge
        q["code_challenge_method"] = code_challenge_method

    auth_url = f"{AUTH_URL}?{urlparse.urlencode(q)}"

    # Try to bind the port first to fail fast if in use
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError as e:
            print(f"Error: cannot bind to 127.0.0.1:{port} ({e}). Is another process using this port?")
            raise SystemExit(2)

    if not args.no_browser:
        _maybe_open_browser(auth_url)
    else:
        print("\nOpen this URL in your browser:\n")
        print(auth_url, "\n")

    print(f"Waiting for redirect on {redirect_uri} ... (timeout 5 minutes)")
    try:
        params = run_local_server(expected_state=state, port=port, timeout=300)
    except Exception as e:
        print(f"Error while running local server: {e}")
        raise

    if "error" in params:
        raise SystemExit(f"Authorization error from Reddit: {params['error']}")

    code = params.get("code")
    if not code:
        raise SystemExit("No 'code' received from Reddit redirect.")

    print("Code received, exchanging for tokens...")
    try:
        token_data = exchange_code_for_token(
            client_id=client_id,
            client_secret=client_secret,
            code=code,
            user_agent=user_agent,
            redirect_uri=redirect_uri,
            use_pkce=args.pkce,
            code_verifier=code_verifier,
        )
    except requests.HTTPError as e:
        print("HTTP error while exchanging code for token:\n", e)
        raise

    # Show a concise summary (mask sensitive bits)
    print("\nToken response (sanitized):")
    for k, v in token_data.items():
        if k in {"access_token", "refresh_token"}:
            print(f"  {k}: {_mask(v)}")
        else:
            print(f"  {k}: {v}")

    # Save if requested
    if args.save:
        env_path = os.path.join(os.getcwd(), ".env")
        if not os.path.exists(env_path):
            open(env_path, "a").close()
        load_dotenv(env_path)
        rt = token_data.get("refresh_token")
        if not rt and args.duration == "permanent":
            print("\nWarning: No refresh_token in response. Double-check your app type, duration=permanent, and scopes.")
        else:
            set_key(env_path, "REDDIT_REFRESH_TOKEN", rt or "")
        set_key(env_path, "REDDIT_CLIENT_ID", client_id)
        # Save secret only if present (script apps)
        if client_secret is not None:
            set_key(env_path, "REDDIT_CLIENT_SECRET", client_secret or "")
        set_key(env_path, "REDDIT_USER_AGENT", user_agent)
        set_key(env_path, "REDIRECT_PORT", str(port))
        set_key(env_path, "REDDIT_SCOPES", scope_str)
        set_key(env_path, "REDDIT_DURATION", args.duration)
        print(f"\nSaved tokens/creds to {env_path}")

    print("\nDone.")

if __name__ == "__main__":
    main()
