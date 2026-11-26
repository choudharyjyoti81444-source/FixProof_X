import os
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

import database
from scanner import scan_website
from reports import generate_pdf
from risk_engine import get_risk_summary


app = Flask(__name__)

app.secret_key = os.environ.get(
    "FIXPROOF_SECRET_KEY",
    "fixproofx-development-secret-change-before-deployment"
)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


def required_login(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        created = database.create_user(name, email, hashed_password)

        if not created:
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for("login"))

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = database.get_user_by_email(email)

        if user and check_password_hash(user["password"], password):

            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]

            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()
    flash("You have been logged out.", "info")

    return redirect(url_for("home"))


@app.route("/dashboard")
@required_login
def dashboard():

    user_id = session["user_id"]

    scans = database.get_user_scans(user_id)

    total_scans = len(scans)

    latest_scan = None

    if scans:
        latest_scan = database.get_scan(scans[0]["id"], user_id)

    return render_template(
        "dashboard.html",
        scans=scans,
        total_scans=total_scans,
        latest_scan=latest_scan,
        security_checks=10,
        user_name=session.get("user_name", "User")
    )


@app.route("/scan", methods=["POST"])
@required_login
def scan():

    website_url = request.form.get("url", "").strip()

    if not website_url:
        flash("Please enter a website URL.", "danger")
        return redirect(url_for("dashboard"))

    try:

        scan_data = scan_website(website_url)

        scan_id = database.save_scan(
            session["user_id"],
            scan_data["url"],
            scan_data["score"],
            scan_data["risk_level"],
            scan_data["results"],
            scan_data.get("technologies", [])
        )

        flash("Website scan completed successfully.", "success")

        return redirect(url_for("scan_result", scan_id=scan_id))

    except ValueError as error:

        flash(str(error), "danger")
        return redirect(url_for("dashboard"))

    except Exception:

        app.logger.exception("Unexpected scan error")

        flash(
            "An unexpected error occurred during scanning.",
            "danger"
        )

        return redirect(url_for("dashboard"))


@app.route("/report/<int:scan_id>")
@required_login
def scan_result(scan_id):

    data = database.get_scan(scan_id, session["user_id"])

    if not data:
        return "Report not found.", 404

    data["risk_summary"] = get_risk_summary(data["results"])

    return render_template("scan_result.html", data=data)


@app.route("/download/<int:scan_id>")
@required_login
def download(scan_id):

    data = database.get_scan(scan_id, session["user_id"])

    if not data:
        return "Report not found.", 404

    data["risk_summary"] = get_risk_summary(data["results"])

    pdf_buffer = generate_pdf(data)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name="FixProofX_Report.pdf",
        mimetype="application/pdf"
    )


@app.errorhandler(404)
def page_not_found(error):
    return "Page not found.", 404


@app.errorhandler(413)
def file_too_large(error):
    return "Request is too large.", 413


if __name__ == "__main__":

    database.init_db()

    print("FixProof X is starting...")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )