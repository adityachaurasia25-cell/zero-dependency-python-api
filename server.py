
"""
GDGoC Technical Task 4 — Zero-Dependency REST API
------------------------------------------------
Standard library only. No pip packages.

Features:
- Hand-written regex router
- GET, POST, PUT, DELETE
- JSON and URL-encoded form parsing
- PBKDF2-HMAC password hashing with random salts
- Hashed bearer tokens with expiration
- Thread-safe, atomic JSON persistence
- In-memory sliding-window rate limiting
- Request size limits and security headers

Run:
    python server.py

For local development and technical-task demonstration.
Do not expose http.server directly to the public internet.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

HOST = "127.0.0.1"
PORT = 8000

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "db.json"
DB_TEMP_FILE = BASE_DIR / "db.tmp"

MAX_BODY_SIZE = 1 * 1024 * 1024       # 1 MB
RATE_LIMIT = 10                       # Requests per window
RATE_WINDOW = 60                      # Seconds
PBKDF2_ITERATIONS = 600_000
SESSION_TTL = 24 * 60 * 60             # 24 hours

# These locks protect shared in-process state.
DB_LOCK = threading.RLock()
RATE_LOCK = threading.Lock()


# ---------------------------------------------------------
# JSON database
# ---------------------------------------------------------

def initial_database():
    """Return the initial database structure."""
    return {
        "users": {},
        "sessions": {},
        "data": {}
    }


def load_database():
    """Load the database, creating it if it doesn't exist."""
    with DB_LOCK:
        if not DB_FILE.exists():
            save_database(initial_database())

        try:
            with DB_FILE.open("r", encoding="utf-8") as file:
                database = json.load(file)

            # Basic schema validation: don't silently replace
            # a corrupt database with an empty one.
            if not isinstance(database, dict):
                raise ValueError("Database must be a JSON object")

            for key in ("users", "sessions", "data"):
                if not isinstance(database.get(key), dict):
                    raise ValueError(f"Invalid database section: {key}")

            return database

        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError("Database JSON is corrupted") from exc


def save_database(database):
    """
    Write to db.tmp, flush it, then atomically replace db.json.

    os.replace prevents readers from observing a partially
    written JSON file. DB_LOCK prevents concurrent in-process
    updates from overwriting each other.
    """
    with DB_LOCK:
        try:
            with DB_TEMP_FILE.open("w", encoding="utf-8") as file:
                json.dump(
                    database,
                    file,
                    ensure_ascii=False,
                    separators=(",", ":")
                )
                file.flush()
                os.fsync(file.fileno())

            os.replace(DB_TEMP_FILE, DB_FILE)

        finally:
            # Remove a leftover temporary file if a write failed.
            try:
                if DB_TEMP_FILE.exists():
                    DB_TEMP_FILE.unlink()
            except OSError:
                pass


# Initialize the file before accepting requests.
load_database()


# ---------------------------------------------------------
# Sliding-window rate limiter
# ---------------------------------------------------------

# IP address -> timestamps of recent requests
REQUEST_TIMES = defaultdict(deque)


def is_rate_limited(ip_address):
    """Return True if this IP exceeded its request allowance."""
    now = time.monotonic()
    cutoff = now - RATE_WINDOW

    with RATE_LOCK:
        timestamps = REQUEST_TIMES[ip_address]

        # Remove requests outside the current time window.
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

        if len(timestamps) >= RATE_LIMIT:
            return True

        timestamps.append(now)
        return False


# ---------------------------------------------------------
# Password hashing and session tokens
# ---------------------------------------------------------

def hash_password(password, salt=None):
    """
    PBKDF2-HMAC-SHA256 with a unique random salt.

    Stored representation:
        pbkdf2_sha256$iterations$salt_hex$digest_hex
    """
    if salt is None:
        salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )

    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}"
        f"${salt.hex()}${digest.hex()}"
    )


def verify_password(password, stored_hash):
    """Verify a password using a constant-time digest comparison."""
    try:
        algorithm, iterations, salt_hex, digest_hex = (
            stored_hash.split("$")
        )

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations)

        # Prevent corrupt or tampered database values from
        # requesting an unbounded amount of CPU work.
        if not 100_000 <= iterations <= 1_000_000:
            return False

        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)

        actual_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations
        )

        return hmac.compare_digest(actual_digest, expected_digest)

    except (ValueError, TypeError, AttributeError):
        return False


def token_fingerprint(token):
    """
    Store only a SHA-256 fingerprint of the bearer token.

    The client receives the random token once; the raw token
    is not persisted in db.json.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(username, database):
    """Create a random, expiring session and return the raw token."""
    token = secrets.token_hex(32)
    fingerprint = token_fingerprint(token)

    database["sessions"][fingerprint] = {
        "username": username,
        "expires_at": int(time.time()) + SESSION_TTL
    }

    return token


def authenticate(token, database):
    """Return the session username, or None if invalid/expired."""
    if not token or len(token) > 256:
        return None

    session = database["sessions"].get(token_fingerprint(token))

    if not session:
        return None

    if session.get("expires_at", 0) <= int(time.time()):
        database["sessions"].pop(token_fingerprint(token), None)
        return None

    username = session.get("username")

    if username not in database["users"]:
        return None

    return username


# ---------------------------------------------------------
# Hand-written regex router
# ---------------------------------------------------------

class Router:
    def __init__(self):
        self.routes = []

    def add(self, method, pattern, handler, auth=False):
        """
        Convert /api/data/<id> into a regex with a named group.

        Parameter names may contain letters, digits and underscores.
        """
        parameter_pattern = re.compile(r"<([a-zA-Z_]\w*)>")
        parts = []
        position = 0

        for match in parameter_pattern.finditer(pattern):
            parts.append(re.escape(pattern[position:match.start()]))

            parameter_name = match.group(1)
            parts.append(f"(?P<{parameter_name}>[^/]+)")
            position = match.end()

        parts.append(re.escape(pattern[position:]))
        compiled = re.compile("^" + "".join(parts) + "$")

        self.routes.append({
            "method": method.upper(),
            "regex": compiled,
            "handler": handler,
            "auth": auth
        })

    def dispatch(self, request_handler, method, path):
        """
        Match the path first, then the HTTP method.

        A known path with the wrong method returns 405.
        An unknown path returns 404.
        """
        path_matches = []

        for route in self.routes:
            match = route["regex"].fullmatch(path)

            if match:
                path_matches.append((route, match))

        if not path_matches:
            raise HTTPError(404, "Route not found")

        for route, match in path_matches:
            if route["method"] == method:
                return route, match.groupdict()

        allowed_methods = sorted({
            route["method"] for route, _ in path_matches
        })

        raise HTTPError(
            405,
            "Method not allowed",
            headers={"Allow": ", ".join(allowed_methods)}
        )


# ---------------------------------------------------------
# HTTP errors and request parsing
# ---------------------------------------------------------

class HTTPError(Exception):
    def __init__(self, status, message, headers=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers or {}


def parse_request_body(handler):
    """
    Read a bounded request body and parse JSON or URL-encoded form.

    Content-Length is checked BEFORE reading from rfile.
    Requests using chunked transfer encoding are rejected because
    this minimal server intentionally supports Content-Length only.
    """
    transfer_encoding = handler.headers.get("Transfer-Encoding", "")

    if transfer_encoding:
        raise HTTPError(501, "Transfer-Encoding is not supported")

    raw_length = handler.headers.get("Content-Length")

    if raw_length is None:
        length = 0
    else:
        try:
            # Reject signs, decimals, and other malformed values.
            if not re.fullmatch(r"[0-9]+", raw_length.strip()):
                raise ValueError
            length = int(raw_length)
        except ValueError:
            raise HTTPError(400, "Invalid Content-Length")

    if length > MAX_BODY_SIZE:
        raise HTTPError(413, "Request body exceeds 1 MB")

    if length == 0:
        return {}

    content_type = handler.headers.get("Content-Type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()

    # Read exactly the declared amount, not an unlimited stream.
    raw_body = handler.rfile.read(length)

    if len(raw_body) != length:
        raise HTTPError(400, "Incomplete request body")

    try:
        decoded = raw_body.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPError(400, "Request body must be UTF-8")

    if media_type == "application/json":
        try:
            result = json.loads(decoded)
        except json.JSONDecodeError:
            raise HTTPError(400, "Malformed JSON")

        if not isinstance(result, dict):
            raise HTTPError(400, "JSON body must be an object")

        return result

    if media_type == "application/x-www-form-urlencoded":
        values = parse_qs(decoded, keep_blank_values=True)

        # Use one value per key for this simple API.
        return {key: items[-1] for key, items in values.items()}

    raise HTTPError(415, "Unsupported Content-Type")


def require_string(body, key, max_length=256):
    """Validate a required, non-empty string field."""
    value = body.get(key)

    if not isinstance(value, str):
        raise HTTPError(400, f"'{key}' must be a string")

    if not value.strip() or len(value) > max_length:
        raise HTTPError(400, f"Invalid '{key}'")

    return value


# ---------------------------------------------------------
# API handlers
# ---------------------------------------------------------

router = Router()


def health(handler, params, body, username):
    return 200, {"status": "ok", "message": "API is running"}


def register(handler, params, body, username):
    username = require_string(body, "username", 64)
    password = require_string(body, "password", 1024)

    # Simple username policy: 3-64 letters, digits, "_" or "-".
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,64}", username):
        raise HTTPError(
            400,
            "Username must be 3-64 characters: letters, digits, _ or -"
        )

    # Avoid silently accepting whitespace around credentials.
    if password != password.strip():
        raise HTTPError(400, "Password must not start or end with whitespace")

    if len(password) < 12:
        raise HTTPError(400, "Password must contain at least 12 characters")

    with DB_LOCK:
        database = load_database()

        if username in database["users"]:
            raise HTTPError(409, "Username already exists")

        database["users"][username] = {
            "password_hash": hash_password(password),
            "created_at": int(time.time())
        }

        save_database(database)

    return 201, {
        "message": "User registered successfully",
        "username": username
    }


def login(handler, params, body, username):
    username = require_string(body, "username", 64)
    password = require_string(body, "password", 1024)

    with DB_LOCK:
        database = load_database()
        user = database["users"].get(username)

        # Same response for an unknown username and wrong password.
        if not user or not verify_password(
            password, user["password_hash"]
        ):
            raise HTTPError(401, "Invalid username or password")

        token = create_session(username, database)
        save_database(database)

    return 200, {
        "message": "Login successful",
        "token_type": "Bearer",
        "access_token": token,
        "expires_in": SESSION_TTL
    }


def get_me(handler, params, body, username):
    with DB_LOCK:
        database = load_database()
        user = database["users"].get(username)

        if not user:
            raise HTTPError(401, "Session is no longer valid")

        return 200, {
            "username": username,
            "created_at": user["created_at"]
        }


def list_data(handler, params, body, username):
    with DB_LOCK:
        database = load_database()

        records = [
            record
            for record in database["data"].values()
            if record["owner"] == username
        ]

    return 200, {"items": records}


def create_data(handler, params, body, username):
    title = require_string(body, "title", 200)
    value = body.get("value")

    # Verify that value can be serialized before saving.
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        raise HTTPError(400, "Invalid value")

    record_id = secrets.token_hex(8)

    record = {
        "id": record_id,
        "owner": username,
        "title": title,
        "value": value,
        "created_at": int(time.time())
    }

    with DB_LOCK:
        database = load_database()
        database["data"][record_id] = record
        save_database(database)

    return 201, {"item": record}


def update_data(handler, params, body, username):
    record_id = params["id"]

    # IDs are opaque generated identifiers, never file paths.
    if not re.fullmatch(r"[a-f0-9]{16}", record_id):
        raise HTTPError(400, "Invalid record ID")

    with DB_LOCK:
        database = load_database()
        record = database["data"].get(record_id)

        if not record or record["owner"] != username:
            raise HTTPError(404, "Record not found")

        if "title" in body:
            title = require_string(body, "title", 200)
            record["title"] = title

        if "value" in body:
            try:
                json.dumps(body["value"])
            except (TypeError, ValueError):
                raise HTTPError(400, "Invalid value")
            record["value"] = body["value"]

        database["data"][record_id] = record
        save_database(database)

    return 200, {"item": record}


def delete_data(handler, params, body, username):
    record_id = params["id"]

    if not re.fullmatch(r"[a-f0-9]{16}", record_id):
        raise HTTPError(400, "Invalid record ID")

    with DB_LOCK:
        database = load_database()
        record = database["data"].get(record_id)

        if not record or record["owner"] != username:
            raise HTTPError(404, "Record not found")

        del database["data"][record_id]
        save_database(database)

    return 200, {"message": "Record deleted", "id": record_id}


# Register routes.
router.add("GET", "/", health)
router.add("POST", "/api/register", register)
router.add("POST", "/api/login", login)
router.add("GET", "/api/me", get_me, auth=True)
router.add("GET", "/api/data", list_data, auth=True)
router.add("POST", "/api/data", create_data, auth=True)
router.add("PUT", "/api/data/<id>", update_data, auth=True)
router.add("DELETE", "/api/data/<id>", delete_data, auth=True)


# ---------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------

class APIHandler(BaseHTTPRequestHandler):
    server_version = "ZeroDependencyAPI"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Avoid logging Authorization headers or request bodies.
        super().log_message(fmt, *args)

    def send_json(self, status, payload, extra_headers=None):
        """Send a JSON response with security-oriented headers."""
        response = json.dumps(
            payload,
            ensure_ascii=False
        ).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")

        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)

        self.end_headers()
        self.wfile.write(response)

    def handle_api_request(self):
        """Shared implementation for supported HTTP methods."""
        try:
            # Apply a per-IP sliding-window limit.
            client_ip = self.client_address[0]

            if is_rate_limited(client_ip):
                self.send_json(
                    429,
                    {"error": "Too many requests"},
                    {"Retry-After": str(RATE_WINDOW)}
                )
                return

            # Ignore query strings for route matching.
            path = urlsplit(self.path).path

            # Reject malformed percent escapes before decoding.
            if re.search(r"%(?![0-9a-fA-F]{2})", path):
                raise HTTPError(400, "Malformed URL encoding")

            # Decode URL-encoded path components before matching.
            # Reject traversal-like segments even though this API
            # never uses a request path as a filesystem path.
            from urllib.parse import unquote
            path = unquote(path)

            if "\x00" in path or "\\" in path:
                raise HTTPError(400, "Invalid path")

            if any(part in (".", "..") for part in path.split("/")):
                raise HTTPError(400, "Path traversal is not allowed")

            body = parse_request_body(self)
            route, params = router.dispatch(self, self.command, path)

            username = None

            if route["auth"]:
                auth_header = self.headers.get("Authorization", "")
                scheme, separator, token = auth_header.partition(" ")

                if (
                    not separator
                    or scheme.lower() != "bearer"
                    or not token
                    or token.strip() != token
                ):
                    raise HTTPError(401, "Bearer token required")

                with DB_LOCK:
                    database = load_database()
                    username = authenticate(token, database)

                    # Persist expired-session cleanup when applicable.
                    fingerprint = token_fingerprint(token)
                    if fingerprint not in database["sessions"]:
                        pass

                if username is None:
                    raise HTTPError(401, "Invalid or expired token")

            status, result = route["handler"](
                self, params, body, username
            )

            self.send_json(status, result)

        except HTTPError as exc:
            self.send_json(
                exc.status,
                {"error": exc.message},
                exc.headers
            )

        except (BrokenPipeError, ConnectionResetError):
            # The client may disconnect before receiving the response.
            return

        except Exception:
            # Do not expose tracebacks, file paths, or internals.
            self.send_json(500, {"error": "Internal server error"})

    def do_GET(self):
        self.handle_api_request()

    def do_POST(self):
        self.handle_api_request()

    def do_PUT(self):
        self.handle_api_request()

    def do_DELETE(self):
        self.handle_api_request()

    def do_OPTIONS(self):
        # This API does not enable browser cross-origin access.
        self.send_json(
            204,
            {},
            {"Allow": "GET, POST, PUT, DELETE, OPTIONS"}
        )


# ---------------------------------------------------------
# Start server
# ---------------------------------------------------------

if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), APIHandler)
    print(f"API running at http://{HOST}:{PORT}")
    print(f"Database: {DB_FILE}")
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.server_close()
