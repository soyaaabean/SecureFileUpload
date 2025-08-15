import os # To handle the file paths
import secrets # This is to generate secure random file names
from datetime import timedelta

from flask import Flask, render_template, redirect, url_for, request, flash
from flask import session
from flask_login import (
    LoginManager, login_user, login_required, logout_user, current_user, UserMixin
)
from flask import send_from_directory # To serve downloads securely
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy import String as SAString

from dotenv import load_dotenv

from sqlalchemy import ForeignKey, DateTime # Obv for file table in the Data Base
from datetime import datetime # To store upload timings

from flask_wtf import CSRFProtect

from flask_wtf.file import FileField, FileAllowed, FileRequired

from werkzeug.exceptions import RequestEntityTooLarge
from flask import Flask, flash, redirect, url_for


# App initialization and secure configuration #
# ---------------------------------------------

load_dotenv()  # Load environment variables from .env (not committed to git)

def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # SECRET_KEY: never hardcode in code; read from env. Fail fast if missing.
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise RuntimeError("SECRET_KEY is not set. Create a .env file (see .env.example).")
    app.config["SECRET_KEY"] = secret_key
    
    # for CSRF protection
    csrf = CSRFProtect(app)

    # Database (SQLite via SQLAlchemy). URL also comes from env for flexibility.
    db_url = os.getenv("DATABASE_URL", "sqlite:///database.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url

    # Secure session cookie settings (defense-in-depth)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Enable this when serving over HTTPS locally or in production
    app.config["SESSION_COOKIE_SECURE"] = False  # set True behind HTTPS needs to be checked
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

    # Database engine & ORM base (Object-Relational Mapper, allows developers to interact directly with objects than writing raw SQL queries)
    engine = create_engine(db_url, echo=False, future=True)

    class Base(DeclarativeBase):
        pass

    class User(Base, UserMixin):
        __tablename__ = "users"
        id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
        username: Mapped[str] = mapped_column(SAString(64), unique=True, index=True)
        password_hash: Mapped[str] = mapped_column(SAString(255))

        def set_password(self, password: str):
            self.password_hash = generate_password_hash(password)

        def check_password(self, password: str) -> bool:
            return check_password_hash(self.password_hash, password)

    class File(Base):
        __tablename__ = "files"
        id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
        original_name: Mapped[str] = mapped_column(SAString(255)) # What the user uploaded
        stored_name: Mapped[str] = mapped_column(SAString(255), unique=True) # The random secure name
        user_id: Mapped[int] = mapped_column(ForeignKey("users.id")) # Makes sure only the uploader can have access 
        uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow) # For sorting and history

    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads") # Since outside static, files cant be accesed directly
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB limit allowed
    #app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB limit for testing

    # Error handler for files that are too big
    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(e):
        flash("File is too large! Please upload a smaller file.", "error")
        return redirect(url_for("dashboard"))



    ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt"}

    def allowed_file(filename):
        return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

    # Create tables if theres none existing
    # This is to include it (it already will, since File is also a Base subclass).
    # This ensures when the app is run, SQLite will automatically create the files table.
    Base.metadata.create_all(engine) 

    # Flask-Login setup
    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str):
        with Session(engine) as db:
            return db.get(User, int(user_id))

    # Forms (Flask-WTF provides CSRF out of the box via hidden field) #
    # -------------------------------------------------------------
    username_rules = Regexp(
        r"^[A-Za-z0-9_]{3,32}$",
        message="Username must be 3-32 characters, letters/numbers/underscore only.",
    )

    class RegisterForm(FlaskForm):
        username = StringField("Username", validators=[InputRequired(), username_rules])
        password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=128)])
        submit = SubmitField("Create account")

    class LoginForm(FlaskForm):
        username = StringField("Username", validators=[InputRequired(), username_rules])
        password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=128)])
        submit = SubmitField("Log in")

    class UploadForm(FlaskForm):
    # file field is required and only allows certain extensions
        file = FileField("File", validators=[
            FileRequired(),   # file must be selected
            FileAllowed(ALLOWED_EXTENSIONS, "Invalid file type!")  # only allowed types
        ])
        submit = SubmitField("Upload")

    # Routes #
    # --------
    @app.get("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():
            with Session(engine) as db:
                # Ensures username is unique
                exists = db.scalar(select(User).where(User.username == form.username.data))
                if exists:
                    flash("Username already taken.", "error")
                    return render_template("register.html", form=form)

                user = User(username=form.username.data)
                user.set_password(form.password.data)
                db.add(user)
                db.commit()
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            with Session(engine) as db:
                user = db.scalar(select(User).where(User.username == form.username.data))
                if user and user.check_password(form.password.data):
                    login_user(user, remember=True)
                    flash("Welcome back!", "success")
                    return redirect(url_for("dashboard"))
                flash("Invalid username or password, try again!", "error")
        return render_template("login.html", form=form)

    # Adding this after Login route makes sure only logged in users can upload by validating
    # Generating a random storgae filename which saves the metadata to DB
    @app.route("/upload", methods=["GET", "POST"]) 
    @login_required
    def upload_file():
        # Uses the UploadForm class 
        form = UploadForm()
    
    # validate_on_submit() checks CSRF token and file validity automatically
        if form.validate_on_submit():
            file = form.file.data  # get the uploaded file
            ext = file.filename.rsplit(".", 1)[1].lower()
            random_name = secrets.token_hex(16) + "." + ext
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], random_name))

        # Saves metadata to database
            with Session(engine) as db:
                new_file = File(
                    original_name=file.filename,
                    stored_name=random_name,
                    user_id=current_user.id
                )
                db.add(new_file)
                db.commit()

            flash("File uploaded successfully", "success")
            return redirect(url_for("list_files"))

        # Rendering the template with the form object
        return render_template("upload.html", form=form)

    # Preventing others accessing the file by listing only the files from the user only
    @app.route("/files")
    @login_required
    def list_files():
        with Session(engine) as db:
            files = db.query(File).filter(File.user_id == current_user.id).all()
        return render_template("files.html", files=files)

    # By serving with the original filename for dowanloading, it checks that the logged in user it belongs to
    @app.route("/download/<int:file_id>")
    @login_required
    def download_file(file_id):
        with Session(engine) as db:
            file_entry = db.query(File).filter(
                File.id == file_id,
                File.user_id == current_user.id
            ).first()
            if not file_entry:
                flash("File not found or access denied", "danger")
                return redirect(url_for("list_files"))

        return send_from_directory(
            app.config["UPLOAD_FOLDER"],
            file_entry.stored_name,
            as_attachment=True,
            download_name=file_entry.original_name
        )

    @app.get("/logout")
    @login_required
    def logout():
        logout_user()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard", methods = ["GET", "POST"])
    @login_required
    def dashboard():
        form = UploadForm()  # Create upload form instance
        files = []

        # Fetching users files from DB
        with Session(engine) as db:
            files = db.query(File).filter(File.user_id == current_user.id).all()

        # Handling the file uploads
        if form.validate_on_submit(): # For the POST request handling
            file = form.file.data
            if file:
                ext = file.filename.rsplit(".", 1)[1].lower()
                random_name = secrets.token_hex(16) + "." + ext
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], random_name))

                with Session(engine) as db:
                    new_file = File(
                        original_name=file.filename,
                        stored_name=random_name,
                        user_id=current_user.id
                    )
                    db.add(new_file)
                    db.commit()
            
                flash("File uploaded successfully", "success")
                return redirect(url_for("dashboard"))  # Refresh dashboard to show new file

        return render_template("dashboard.html", username=current_user.username, form=form, files=files)

    # Security header (basic) 
    # Extra security instructions for every response the Flask app send to the browser
    @app.after_request
    def add_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff" # This tells the browser to not guess any files but to allow only the ones we declared as safe, to stop attacks where it tricks the browser to run a dangerous file
        resp.headers["X-Frame-Options"] = "DENY" # Stops the site to load in an <iframe> on another site. Protects againts clickjacking
        resp.headers["X-XSS-Protection"] = "0" # This would disable the XSS (Cross-Site Scripting) old, builtin filter on the web browser.
        return resp                            # Could sometimes be safer since the old filter could be bypasses, and nowadays the web browsers more rely on CSP (Content Security Policy)

    return app


app = create_app()

if __name__ == "__main__":
    # For local dev only. In production, using a WSGI server (gunicorn/uwsgi) and HTTPS is recommended.
    app.run(debug=True)
