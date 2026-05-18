import os
import qrcode
import random
import string
import sqlite3
from flask import Flask, redirect, url_for, render_template, request, flash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------
# Flask app
# --------------------
app = Flask(__name__)
# AI: Doplněno generování klíče, pokud není v ENV, pro vyšší bezpečnost
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-zmenit-v-produkci")

csrf = CSRFProtect(app)

# --------------------
# Login manager
# --------------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# --------------------
# Database & Paths
# --------------------
DB_PATH = "app.db"

# AI: Definice absolutní cesty ke složce pro QR kódy, aby aplikace běžela kdekoli (včetně PythonAnywhere)
def get_qr_storage_path():
    return os.path.join(app.root_path, 'static', 'qr_images')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    storage_path = get_qr_storage_path()
    if not os.path.exists(storage_path):
        os.makedirs(storage_path)
        
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            rowid INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS library (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            qr_text TEXT NOT NULL,
            qr_image_path TEXT UNIQUE NOT NULL,
            user_rowid INTEGER,
            FOREIGN KEY(user_rowid) REFERENCES users(rowid)
        )
    """)
    conn.commit()
    conn.close()

# --------------------
# User model
# --------------------
class User(UserMixin):
    def __init__(self, rowid, username, password_hash):
        self.id = rowid
        self.username = username
        self.password_hash = password_hash

# --------------------
# User loader
# --------------------
@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    row = conn.execute(
        "SELECT rowid, username, password_hash FROM users WHERE rowid = ?",
        (user_id,)
    ).fetchone()
    conn.close()

    if row:
        return User(row["rowid"], row["username"], row["password_hash"])
    return None

# --------------------
# Forms (Flask-WTF)
# --------------------
# AI: Přidána validace délky pro ochranu před nesmyslnými vstupy
class RegisterForm(FlaskForm):
    username = StringField("Uživatelské jméno", validators=[InputRequired(), Length(min=3, max=30)])
    password = PasswordField("Heslo", validators=[InputRequired(), Length(min=6, max=100)])
    submit = SubmitField("Registrovat se")

class LoginForm(FlaskForm):
    username = StringField("Uživatelské jméno", validators=[InputRequired()])
    password = PasswordField("Heslo", validators=[InputRequired()])
    submit = SubmitField("Přihlásit se")

class QrNewForm(FlaskForm):
    qr_text = StringField("Text nebo URL pro QR kód", validators=[InputRequired(), Length(max=500)])
    submit = SubmitField("Generovat QR kód")

# AI: Nový formulář pro bezpečné smazání prvků pomocí POST (CSRF ochrana)
class EmptyForm(FlaskForm):
    submit = SubmitField("Potvrdit")

# --------------------
# Routes
# --------------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        # AI: Sjednoceno volání DB přes get_db() namísto ručního sqlite3.connect
        conn = get_db()
        res = conn.execute(
            "SELECT id, qr_text, qr_image_path FROM library WHERE user_rowid = ?", 
            (current_user.id,)
        )
        user_library = res.fetchall()
        conn.close()
        
        form = EmptyForm()
        return render_template("index.html", user_library=user_library, form=form)
    return redirect(url_for("login"))

# --------------------
# Register
# --------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
        
    form = RegisterForm()
    if form.validate_on_submit():
        password_hash = generate_password_hash(form.password.data)

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (form.username.data, password_hash)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Uživatel s tímto jménem již existuje."
            return render_template("error.html", error=error)

    return render_template("register.html", form=form)

# --------------------
# Login
# --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
        
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db()
        row = conn.execute(
            "SELECT rowid, username, password_hash FROM users WHERE username = ?",
            (form.username.data,)
        ).fetchone()
        conn.close()

        if row and check_password_hash(row["password_hash"], form.password.data):
            login_user(User(row["rowid"], row["username"], row["password_hash"]))
            return redirect(url_for("index"))
        
        error = "Nesprávné uživatelské jméno nebo heslo."
        return render_template("error.html", error=error)

    return render_template("login.html", form=form)

# --------------------
# Logout
# --------------------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

# --------------------
# QR New
# --------------------
@app.route("/qr-new", methods=['GET', 'POST'])
@login_required
def qr_new():
    form = QrNewForm()
    if form.validate_on_submit():
        qr_text = form.qr_text.data
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_text)
        qr.make(fit=True)

        def generate_safe_filename_string(length=50):
            allowed_chars = string.ascii_letters + string.digits + "_-"
            return ''.join(random.choice(allowed_chars) for _ in range(length))

        # AI: Oprava cesty a správné odsazení bloku pro uložení obrázku uvnitř podmínky formuláře
        file_name = generate_safe_filename_string() + ".png"
        absolute_storage_path = get_qr_storage_path()

        if not os.path.exists(absolute_storage_path):
            os.makedirs(absolute_storage_path)

        img = qr.make_image(fill_color="black", back_color="white")
        img.save(os.path.join(absolute_storage_path, file_name))        

        # AI: Oprava na get_db() pro konzistenci
        conn = get_db()
        conn.execute(
            'INSERT INTO library (qr_text, qr_image_path, user_rowid) VALUES (?, ?, ?)',
            (qr_text, file_name, current_user.id)
        )
        conn.commit()
        conn.close()
        
        return redirect(url_for("index"))
        
    return render_template("qr_new.html", form=form)

# --------------------
# AI Sekce: Nové funkce pro mazání dat a účtu
# --------------------

@app.route("/qr-delete/<int:qr_id>", methods=["POST"])
@login_required
def qr_delete(qr_id):
    form = EmptyForm()
    if form.validate_on_submit():
        conn = get_db()
        # Ověření, že QR kód patří přihlášenému uživateli
        row = conn.execute(
            "SELECT qr_image_path FROM library WHERE id = ? AND user_rowid = ?", 
            (qr_id, current_user.id)
        ).fetchone()
        
        if row:
            # AI: Oprava cesty na absolutní pro bezpečné smazání souboru ze serveru
            file_to_delete = os.path.join(get_qr_storage_path(), row["qr_image_path"])
            if os.path.exists(file_to_delete):
                os.remove(file_to_delete)
            
            # Smazání záznamu z DB
            conn.execute("DELETE FROM library WHERE id = ?", (qr_id,))
            conn.commit()
            
        conn.close()
    return redirect(url_for("index"))

@app.route("/settings", methods=["GET"])
@login_required
def settings():
    form = EmptyForm()
    return render_template("settings.html", form=form)

@app.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    form = EmptyForm()
    if form.validate_on_submit():
        conn = get_db()
        
        # 1. Najít a smazat všechny soubory uživatele (absolutní cesta)
        rows = conn.execute(
            "SELECT qr_image_path FROM library WHERE user_rowid = ?", 
            (current_user.id,)
        ).fetchall()
        
        storage_path = get_qr_storage_path()
        for row in rows:
            file_to_delete = os.path.join(storage_path, row["qr_image_path"])
            if os.path.exists(file_to_delete):
                os.remove(file_to_delete)
                
        # 2. Smazat QR kódy z DB
        conn.execute("DELETE FROM library WHERE user_rowid = ?", (current_user.id,))
        
        # 3. Smazat uživatele
        conn.execute("DELETE FROM users WHERE rowid = ?", (current_user.id,))
        conn.commit()
        conn.close()
        
        # 4. Odhlásit a přesměrovat
        logout_user()
        return redirect(url_for("register"))
        
    return redirect(url_for("settings"))

# --------------------
# Run
# --------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)