# Zero-Dependency Python API
A lightweight REST API built using only Python's standard library for the GDGoC Indore Technical Task 4: Zero-Dependency Build.

## Features
* Custom HTTP router with dynamic path parameters
* JSON and URL-encoded form parsing
* User registration and login
* Secure password hashing using PBKDF2-HMAC
* Token-based authentication
* JSON file-based persistence with atomic writes
* Thread-safe database access
* IP-based rate limiting
* Request body size limits
* Path traversal protection
* HTTP error handling

## Requirements
* Python 3.10 or later
* No third-party Python packages required

## Run locally
1. Clone or download this repository.

2. Open a terminal in the project directory.

3. Run:

   ```bash
   python server.py
   ```

4. Open `http://127.0.0.1:8000/` in your browser.

## API Endpoints
| Method | Endpoint         | Purpose                        |
| ------ | ---------------- | ------------------------------ |
| GET    | `/`              | Health check                   |
| POST   | `/api/register`  | Register a user                |
| POST   | `/api/login`     | Log in                         |
| GET    | `/api/me`        | Get authenticated user details |
| POST   | `/api/data`      | Create a record                |
| GET    | `/api/data`      | List records                   |
| PUT    | `/api/data/<id>` | Update a record                |
| DELETE | `/api/data/<id>` | Delete a record                |

Protected endpoints require an `Authorization: Bearer <token>` header.

## Persistence and security

Application data is stored locally in `db.json`, which is generated at runtime. Passwords should be stored as hashes, never as plaintext.

Do not commit `db.json`, session tokens, or other sensitive information to GitHub.

## Testing

Use cURL or Postman to test registration, login, authenticated requests, CRUD operations, invalid routes, unsupported methods, oversized payloads, and rate limiting.

## Project

Created for GDGoC Indore — Technical Task 4: Zero-Dependency Build.
