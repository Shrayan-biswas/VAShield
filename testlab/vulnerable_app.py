"""
A tiny, deliberately-misconfigured Flask app used ONLY to prove that the
VAShield scanners produce real, correct findings against a target with
known issues. This is our own local sandbox target (127.0.0.1) — not a
third party's system — so it's safe to run intrusive checks against it.

Deliberately includes:
  - Missing security headers
  - Permissive CORS reflecting Origin with credentials
  - A session cookie missing HttpOnly/Secure/SameSite
  - An endpoint vulnerable to error-based SQL injection (sqlite3)
  - An endpoint that reflects input unescaped (XSS)
  - An admin endpoint with no auth check (BFLA)
  - A "user object" endpoint with no ownership check (BOLA)
  - An exposed .env file
"""
import sqlite3
from flask import Flask, request, make_response, jsonify

app = Flask(__name__)

DB = ":memory:"
conn = sqlite3.connect(DB, check_same_thread=False)
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, tenant TEXT, name TEXT, secret TEXT)")
conn.execute("INSERT INTO users VALUES (1,'tenantA','Alice','alice-secret')")
conn.execute("INSERT INTO users VALUES (2,'tenantB','Bob','bob-secret')")
conn.commit()


@app.after_request
def strip_headers_and_set_bad_cookie(resp):
    # Intentionally NOT setting CSP / X-Frame-Options / HSTS / nosniff / Referrer-Policy
    resp.set_cookie("session_token", "demo123", httponly=False, secure=False, samesite=None)
    return resp


@app.route("/")
def index():
    return "VAShield Test Lab — intentionally vulnerable, local only."


@app.route("/api/v1/search")
def search():
    # VULNERABLE: string-concatenated SQL query
    q = request.args.get("search_query", "")
    try:
        cur = conn.execute(f"SELECT name FROM users WHERE name = '{q}'")
        rows = cur.fetchall()
        return jsonify(rows)
    except sqlite3.OperationalError as e:
        return f"Database error (sqlite3.OperationalError): {e}", 500


@app.route("/api/v1/echo")
def echo():
    # VULNERABLE: reflects input unescaped
    msg = request.args.get("msg", "")
    return f"<html><body>You said: {msg}</body></html>"


@app.route("/api/v1/customers/<cust_id>")
def customer(cust_id):
    # VULNERABLE: no ownership check (BOLA) — any authenticated caller gets any customer
    cur = conn.execute("SELECT id,tenant,name,secret FROM users WHERE id=?", (cust_id,))
    row = cur.fetchone()
    if not row:
        return "Not found", 404
    return jsonify({"id": row[0], "tenant": row[1], "name": row[2], "secret": row[3]})


@app.route("/api/v1/admin/purgedata")
def admin_purge():
    # VULNERABLE: no role check at all (BFLA)
    return jsonify({"status": "purged (simulated, no-op in test lab)"})


@app.route("/.env")
def env_leak():
    return "DB_PASSWORD=supersecret123\nAPI_KEY=sk-fake-demo-key", 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055)
