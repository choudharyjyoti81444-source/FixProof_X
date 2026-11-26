
from flask import Flask, request, redirect, url_for, session, flash, render_template_string, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from html import escape
import database
from scanner import scan_website
from reports import generate_pdf

app = Flask(__name__)
app.secret_key = "FixProofX-Development-Secret-Change-Before-Deployment"


STYLE = """
* { box-sizing: border-box; }

body {
    margin: 0;
    background: #080d19;
    color: #e5e7eb;
    font-family: Arial, sans-serif;
}

nav {
    padding: 22px 7%;
    border-bottom: 1px solid #263449;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 15px;
}

a {
    color: #38bdf8;
    text-decoration: none;
}

main {
    max-width: 1100px;
    width: 90%;
    margin: 40px auto;
}

.card {
    background: #111827;
    border: 1px solid #263449;
    border-radius: 14px;
    padding: 24px;
    margin: 18px 0;
}

.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}

h1 { font-size: 34px; }
h2 { color: #38bdf8; }

input {
    display: block;
    width: 100%;
    padding: 14px;
    margin: 12px 0;
    background: #080d19;
    color: white;
    border: 1px solid #334155;
    border-radius: 7px;
}

button, .btn {
    display: inline-block;
    background: #0284c7;
    color: white;
    padding: 13px 20px;
    border: 0;
    border-radius: 7px;
    cursor: pointer;
}

.stat {
    font-size: 30px;
    color: #38bdf8;
}

table {
    width: 100%;
    border-collapse: collapse;
    overflow-wrap: anywhere;
}

td, th {
    text-align: left;
    padding: 12px;
    border-bottom: 1px solid #334155;
}

.good { color: #4ade80; }
.bad { color: #f87171; }
.muted { color: #94a3b8; }

@media(max-width:600px) {
    h1 { font-size: 27px; }
    main { width: 94%; }
    .card { padding: 17px; }
}
"""


def render(title, content):
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{{ title }} | FixProof X</title>
        <style>{{ style }}</style>
    </head>

    <body>
        <nav>
            <a href="/" style="font-size:24px;font-weight:bold">
                FixProof X
            </a>

            <span>
                {% if session.get('user_id') %}
                    <a href="/dashboard">Dashboard</a>
                    &nbsp;
                    <a href="/logout">Logout</a>
                {% else %}
                    <a href="/login">Login</a>
                    &nbsp;
                    <a href="/register">Register</a>
                {% endif %}
            </span>
        </nav>

        <main>
            {% for msg in get_flashed_messages() %}
                <div class="card">{{ msg }}</div>
            {% endfor %}

            {{ content | safe }}
        </main>
    </body>
    </html>
    """, title=title, content=content, style=STYLE)


def required_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    return render("Home", """
    <div class="card" style="text-align:center;padding:65px 20px">
        <h1>Secure Your Digital World</h1>
        <h2>Intelligent Web Security Platform</h2>
        <p class="muted">
            Analyze essential website security headers with FixProof X.
        </p>
        <a class="btn" href="/register">Get Started</a>
        <a class="btn" href="/login">Login</a>
    </div>

    <div class="grid">
        <div class="card">
            <h2>Smart Scanner</h2>
            <p>Check website security headers.</p>
        </div>
        <div class="card">
            <h2>Risk Engine</h2>
            <p>Understand your security score.</p>
        </div>
        <div class="card">
            <h2>PDF Reports</h2>
            <p>Download scan reports.</p>
        </div>
    </div>
    """)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(password) < 8:
            flash("Enter valid details and a password of at least 8 characters.")
        else:
            success = database.create_user(
                name,
                email,
                generate_password_hash(password)
            )

            if success:
                flash("Account created. Please log in.")
                return redirect(url_for("login"))

            flash("This email is already registered.")

    return render("Register", """
    <div class="card">
        <h1>Create Account</h1>
        <form method="post">
            <input name="name" placeholder="Full name" required>
            <input name="email" type="email" placeholder="Email" required>
            <input name="password" type="password"
                   placeholder="Password (8+ characters)"
                   minlength="8" required>
            <button type="submit">Create Account</button>
        </form>
    </div>
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = database.get_user_by_email(email)

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]

            return redirect(url_for("dashboard"))

        flash("Incorrect email or password.")

    return render("Login", """
    <div class="card">
        <h1>Login</h1>
        <form method="post">
            <input name="email" type="email" placeholder="Email" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
    """)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
@required_login
def dashboard():
    try:
        user_id = session["user_id"]
        name = escape(str(session.get("name", "User")))

        scans = database.get_user_scans(user_id)

        rows = ""

        for item in scans:
            scan_id = int(item["id"])
            scan_url = escape(str(item.get("url", "N/A")))
            score = escape(str(item.get("score", 0)))
            risk = escape(str(item.get("risk_level", "Pending")))

            rows += f"""
            <tr>
                <td>{scan_url}</td>
                <td>{score}/100</td>
                <td>{risk}</td>
                <td><a href="/report/{scan_id}">View Report</a></td>
            </tr>
            """

        if not rows:
            rows = '<tr><td colspan="4">No scans yet.</td></tr>'

        content = f"""
        <h1>Welcome, {name}</h1>

        <div class="grid">
            <div class="card">
                <p>Total Scans</p>
                <div class="stat">{len(scans)}</div>
            </div>

            <div class="card">
                <p>Security Checks</p>
                <div class="stat">5</div>
            </div>

            <div class="card">
                <p>Platform</p>
                <div class="stat">Active</div>
            </div>
        </div>

        <div class="card">
            <h2>Website Scanner</h2>
            <form method="post" action="/scan">
                <input name="url"
                       placeholder="https://example.com"
                       required>
                <button type="submit">Start Scan</button>
            </form>
            <p class="muted">
                Only scan websites you own or are authorized to test.
            </p>
        </div>

        <div class="card">
            <h2>Scan History</h2>
            <table>
                <tr>
                    <th>Website</th>
                    <th>Score</th>
                    <th>Risk</th>
                    <th>Report</th>
                </tr>
                {rows}
            </table>
        </div>
        """

        return render("Dashboard", content)

    except Exception:
        app.logger.exception("Dashboard loading failed")
        return "Dashboard loading failed. Check the PowerShell traceback.", 500


@app.route("/scan", methods=["POST"])
@required_login
def scan():
    try:
        result = scan_website(request.form.get("url", ""))

        scan_id = database.save_scan(
            session["user_id"],
            result["url"],
            result["score"],
            result["risk_level"],
            result
        )

        return redirect(url_for("report", scan_id=scan_id))

    except ValueError as error:
        flash(str(error))
        return redirect(url_for("dashboard"))

    except Exception:
        app.logger.exception("Website scan failed")
        flash("Scan failed. Please check the server error.")
        return redirect(url_for("dashboard"))


@app.route("/report/<int:scan_id>")
@required_login
def report(scan_id):
    data = database.get_scan(scan_id, session["user_id"])

    if not data:
        return "Report not found.", 404

    rows = ""

    for item in data["results"].get("results", []):
        status = str(item.get("status", "Unknown"))
        css = "good" if status == "Passed" else "bad"

        rows += f"""
        <tr>
            <td>{escape(str(item.get('name', 'Check')))}</td>
            <td class="{css}">{escape(status)}</td>
            <td>{escape(str(item.get('details', '')))}</td>
        </tr>
        """

    content = f"""
    <div class="card">
        <h1>Security Report</h1>
        <h2>{data['score']}/100</h2>
        <p>Website: {escape(str(data['url']))}</p>
        <p>Risk Level: {escape(str(data['risk_level']))}</p>

        <table>
            <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
            {rows}
        </table>

        <br>
        <a class="btn" href="/download/{int(scan_id)}">Download PDF</a>
        <a class="btn" href="/dashboard">Dashboard</a>
    </div>
    """

    return render("Report", content)


@app.route("/download/<int:scan_id>")
@required_login
def download(scan_id):
    data = database.get_scan(scan_id, session["user_id"])

    if not data:
        return "Report not found.", 404

    pdf_data = dict(data["results"])
    pdf_data["url"] = data["url"]
    pdf_data["score"] = data["score"]
    pdf_data["risk_level"] = data["risk_level"]

    buffer = generate_pdf(pdf_data)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="FixProofX_Report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    database.init_db()
    print("FixProof X is starting...")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )
