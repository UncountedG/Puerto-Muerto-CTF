import sqlite3
import os
from flask import Flask, request, render_template, redirect, url_for, session, g


app = Flask(__name__)
app.secret_key = os.urandom(24)


# The database path is injected at container startup by execute.sh via the
# DB_PATH environment variable. This avoids hardcoding a path that differs
# between build time and runtime, and keeps app.py decoupled from the
# directory structure decisions made in prepare.sh.
DATABASE = os.environ.get("DB_PATH", "/opt/sigeport/db/sigeport.db")

# The HTTP port is injected at container startup by execute.sh via the
# HTTP_PORT environment variable. With network_mode: host the Flask process
# must bind to the exact port the instructor assigned — there is no Docker
# NAT layer to remap from a fixed internal port to an external one.
HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))


def get_db():
    """
    Returns the SQLite connection bound to the current Flask application context.
    The connection is stored on the 'g' proxy object so it is reused within a single
    request lifecycle and closed cleanly when the application context is torn down.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    """
    Closes the SQLite connection at the end of every request context, regardless
    of whether the request completed successfully or raised an exception.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/", methods=["GET", "POST"])
def login():
    """
    Authentication endpoint for the SIGEPORT inspector portal.

    The SQL query is assembled via direct string concatenation without parameterization.
    This makes the login form vulnerable to OR-based authentication bypass, for example:
        inspector_id: ' OR '1'='1
        access_code:  ' OR '1'='1

    Successful authentication — whether legitimate or injected — creates a session and
    redirects to the internal panel. The session inspector_name is set from the first row
    returned by the query, which under a bypass payload will be the first record in the
    inspectors table, not a meaningful identity. This is intentional: it signals to an
    observant player that something is off without making the bypass trivially obvious.
    """
    error = None
    if request.method == "POST":
        inspector_id = request.form.get("inspector_id", "")
        access_code  = request.form.get("access_code", "")

        db = get_db()
        query = (
            "SELECT id, name FROM inspectors "
            "WHERE inspector_id = '" + inspector_id + "' "
            "AND access_code = '" + access_code + "'"
        )
        try:
            row = db.execute(query).fetchone()
        except sqlite3.OperationalError:
            error = "Error en el sistema. Contacte con soporte técnico."
            return render_template("login.html", error=error)

        if row:
            session["logged_in"] = True
            session["inspector_name"] = row["name"]
            return redirect(url_for("panel"))

        error = "Credenciales incorrectas. Acceso denegado."

    return render_template("login.html", error=error)


@app.route("/panel")
def panel():
    """
    Internal inspector panel. Requires an active session established via the login route.

    Displays vessel manifest records from the 'manifests' table. The optional 'vessel'
    GET parameter is injected directly into the WHERE clause without sanitization.

    This is the primary attack surface for the flag extraction. A player must:
        1. Confirm the parameter is injectable (single quote breaks the response).
        2. Determine the column count via ORDER BY or UNION SELECT NULL probing.
        3. Enumerate database tables via sqlite_master:
               ' UNION SELECT name,sql,NULL,NULL FROM sqlite_master WHERE type='table'--
        4. Dump the classified_cargo table:
               ' UNION SELECT manifest_ref,cargo_type,clearance,NULL FROM classified_cargo--

    The 'classified_cargo' table is never referenced anywhere in the visible application,
    so the player must discover it through schema enumeration, not by reading the source.
    """
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    vessel_filter = request.args.get("vessel", "")
    db = get_db()

    if vessel_filter:
        query = (
            "SELECT vessel_name, origin, destination, status "
            "FROM manifests WHERE vessel_name = '" + vessel_filter + "'"
        )
        try:
            manifests = db.execute(query).fetchall()
        except sqlite3.OperationalError:
            manifests = []
    else:
        manifests = db.execute(
            "SELECT vessel_name, origin, destination, status FROM manifests"
        ).fetchall()

    return render_template(
        "panel.html",
        inspector_name=session.get("inspector_name", "Inspector"),
        manifests=manifests,
        vessel_filter=vessel_filter,
    )


@app.route("/logout")
def logout():
    """
    Destroys the current session and redirects to the login page.
    """
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=HTTP_PORT, debug=False)
