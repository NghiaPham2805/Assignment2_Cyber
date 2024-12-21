from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from markupsafe import escape  # Helps prevent XSS by escaping user input
import sqlite3
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.exceptions import BadRequest
import subprocess
import requests
from flask_talisman import Talisman  # Adds security headers to protect against various attacks
from flask_limiter import Limiter  # Rate limiting to prevent abuse
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Required for CSRF protection

# Talisman for enhanced security headers
Talisman(app, content_security_policy={
    'default-src': ["'self'"],
    'script-src': ["'self'"]
})

# Rate limiter setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Database Setup
def init_db():
    
    conn = sqlite3.connect("secure_app.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            name TEXT NOT NULL, 
            email TEXT NOT NULL UNIQUE
        )
    """)
    conn.commit()
    conn.close()

# Input Form
class UserForm(FlaskForm):
    """
    Flask-WTF form for validating user input.
    """
    name = StringField("Name", validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email()])

# Add User Route
@app.route("/add_user", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def add_user():
    
    form = UserForm()
    if form.validate_on_submit():
        name = escape(form.name.data)  # Escape user input to prevent XSS
        email = escape(form.email.data)  # Escape user input to prevent XSS

        conn = sqlite3.connect("secure_app.db")
        cursor = conn.cursor()
        try:
            # Use parameterized queries to protect against SQL injection
            cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
            conn.commit()
            flash("User added successfully!", "success")
        except sqlite3.IntegrityError:
            flash("Email already exists.", "danger")
        finally:
            conn.close()

        return redirect(url_for("add_user"))

    return render_template("add_user.html", form=form)

# Search User Route
@app.route("/search_user", methods=["GET"])
@limiter.limit("5 per minute")
def search_user():

    search_query = escape(request.args.get("query", "")).strip()  # Escape user input to prevent XSS
    results = []

    if search_query:
        conn = sqlite3.connect("secure_app.db")
        cursor = conn.cursor()
        # Perform a case-insensitive search in the database
        cursor.execute(
            "SELECT name, email FROM users WHERE name LIKE ? OR email LIKE ?", 
            (f"%{search_query}%", f"%{search_query}%")
        )
        results = cursor.fetchall()
        conn.close()

    return render_template("search.html", query=results)

# Execute Command Route
@app.route("/execute_command", methods=["POST"])
@limiter.limit("2 per minute")
def execute_command():
    """
    Executes predefined shell commands safely.
    """
    command = request.json.get("command")
    safe_commands = {
        "list": ["ls", "-l"],  # List directory contents
        "status": ["uptime"]  # Show system uptime
    }

    if command not in safe_commands:
        raise BadRequest("Invalid command")

    result = subprocess.run(safe_commands[command], capture_output=True, text=True, check=True)
    return jsonify({"output": result.stdout.strip()})

# Secure Fetch Route
@app.route("/fetch_secure", methods=["GET"])
@limiter.limit("5 per minute")
def fetch_secure():
    
    url = request.args.get("url")
    if not url or not url.startswith("https://"):
        raise BadRequest("Invalid or insecure URL")  # Ensure URL is secure (HTTPS)

    try:
        response = requests.get(url, verify=True, timeout=5)
        return jsonify({"content": response.text[:200]})
    except requests.exceptions.SSLError:
        return jsonify({"error": "SSL verification failed"}), 400
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 400

# Security Headers
@app.after_request
def set_security_headers(response):

    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self';"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

if __name__ == "__main__":
    init_db()
    
    # import ssl
    # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # context.load_cert_chain("cert.pem", "key.pem")  # Provide your SSL certificate and key files
    # app.run(ssl_context=context)  # Use HTTPS to protect against MITM attacks

    app.run(debug=True)