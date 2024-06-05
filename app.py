# import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
import os
import logging
import logging.handlers
import logging.config
import random
from re import sub, search
import smtplib
from email.mime.text import MIMEText
from sqlite3 import OperationalError
from flask import Flask, redirect, render_template, request, session, url_for, flash, has_request_context
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from telethon import TelegramClient, errors
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_utils import UUIDType, EmailType
import uuid
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo, Regexp, NumberRange, Email
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import sentry_sdk
from functools import wraps

load_dotenv()  # take environment variables from .env

# Path init
THIS_FOLDER = Path(__file__).parent.resolve()

# Chars used for random unique code generation (does not incl. Uppercase I and Lowercase l to prevent confusion)
CODE_CHARS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'n', 'm', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
              'E', 'F', 'G', 'H', 'J', 'K', 'N', 'M', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0']

GMAIL_USERNAME = os.environ["GMAIL_USERNAME"]
GMAIL_APP_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]

# Init sentry (REMOVE IF NOT USING SENTRY)
sentry_sdk.init(
    dsn=os.environ['SENTRY_DSN'],
    enable_tracing=True
)

# Create logger
app_logger = logging.getLogger()


class NewFormatter(logging.Formatter):
    """
    Customises default logging formatter, adds flask request context
    """

    def format(self, record):
        if has_request_context():
            record.path = request.path
            record.remote = request.remote_addr
        else:
            record.path = None
            record.remote = None
        return super().format(record)


app_logger.setLevel(logging.INFO)
# Create rotating file handler (0.5 mb maxbytes)
rotate_handler = logging.handlers.RotatingFileHandler(
    f'{THIS_FOLDER}/logs/app.log', maxBytes=1000000, backupCount=2)
# Set the formatter for the handler
formatter = NewFormatter(
    '%(remote)s - [%(asctime)s][%(levelname)s]["%(path)s"] %(threadName)s: %(message)s')
rotate_handler.setFormatter(formatter)
app_logger.addHandler(rotate_handler)

# Log to console/terminal also
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(formatter)
app_logger.addHandler(consoleHandler)


# Init app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = os.environ["APP_SECRET_KEY"]
# recaptcha
app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ["RECAPTCHA_PUBLIC_KEY"]
# recaptcha
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ["RECAPTCHA_PRIVATE_KEY"]

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Flask-login Init
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def require_account_verified(temp):
    """
    Require a verified account to access an endpoint.
    Used as a decorator like @require_account_verified
    """
    def wrapper(func):
        @wraps(func)
        async def wrapped(*args):
            if not current_user.email_verified:
                return redirect(url_for("email_verification"))
            return await func(*args)
        return wrapped
    return wrapper(temp)


class User(db.Model, UserMixin):
    """
    User model for database initialisation.

    Schema update steps:
    0. Delete current instance/database.db
    1. Open python shell in terminal `py`
    2. run `from app import app, db`
    3. run ```with app.app_context():
    db.create_all()```
    """
    id = db.Column(UUIDType(binary=False),
                   primary_key=True, default=uuid.uuid4)
    username = db.Column(EmailType, nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    email_verified = db.Column(db.Boolean, nullable=False,
                               unique=False, default=False)

    email_code = db.Column(db.String(80), nullable=True, unique=False)
    email_code_creation = db.Column(db.DateTime(
        timezone=True), nullable=True, unique=False)

    forgot_password_code = db.Column(
        db.String(80), nullable=True, unique=False)
    forgot_password_code_creation = db.Column(db.DateTime(
        timezone=True), nullable=True, unique=False)

    is_admin = db.Column(db.Boolean, nullable=False,
                         unique=False, default=False)


class Secret(db.Model):
    """
    Secret model for database initialisation.

    Schema update steps:
    0. Delete current instance/database.db
    1. Open python shell in terminal `py`
    2. run `from app import app, db`
    3. run ```with app.app_context():
    db.create_all()```
    """
    id = db.Column(db.Integer,
                   primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=False)
    value = db.Column(db.String(80), nullable=False, unique=False)


class RegisterForm(FlaskForm):
    """
    App Registration Form
    """
    username = EmailField(validators=[InputRequired(), Email(
        granular_message=True, check_deliverability=True)], render_kw={"placeholder": "Email"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=8, max=100), EqualTo('password2', message='Passwords must match')], render_kw={"placeholder": "Password"})

    password2 = PasswordField(validators=[InputRequired()], render_kw={
                              "placeholder": "Confirm Password"})

    access_code = PasswordField(validators=[InputRequired(), Length(
        max=80)], render_kw={"placeholder": "Access Code"})

    recaptcha = RecaptchaField()

    submit = SubmitField("Register")

    def validate_username(self, username):
        """
        Ensures no duplicate username in database
        """
        existing_username = User.query.filter_by(
            username=username.data).first()
        if existing_username:
            self.username.errors += (ValidationError(
                "That email has already been registered"),)

    def validate_access_code(self, access_code):
        """
        Ensures access code matches
        """
        db_access_code = Secret.query.filter_by(
            name="registration_access_code").first()

        if db_access_code is None:
            self.access_code.errors += (ValidationError(
                "No access code found, request assistance from site administrator"),)
        elif db_access_code.value != access_code.data:
            self.access_code.errors += (ValidationError(
                "Invalid access code"),)


class EmailVerificationForm(FlaskForm):
    """
    Email code verification form
    """
    code = StringField(validators=[InputRequired(message="Empty field"), Length(
        min=8, max=8), Regexp("[a-zA-Z0-9]+", message="One or more characters are invalid")], render_kw={})

    submit = SubmitField("Verify")


class ForgotPasswordEmailForm(FlaskForm):
    """
    Forgot Password Form (email for sending unique code)
    """
    username = EmailField(validators=[InputRequired(), Email(
        granular_message=True, check_deliverability=True)], render_kw={"placeholder": "Email"})

    submit = SubmitField("Submit")


class ForgotPasswordUpdateForm(FlaskForm):
    """
    Forgot Password Form (password and code)
    """

    password = PasswordField(validators=[InputRequired(), Length(
        min=8, max=100), EqualTo('password2', message='Passwords must match')], render_kw={"placeholder": "Password"})

    password2 = PasswordField(validators=[InputRequired()], render_kw={
                              "placeholder": "Confirm Password"})

    code = StringField(validators=[InputRequired(message="Empty field"), Length(
        min=8, max=8), Regexp("[a-zA-Z0-9]+", message="One or more characters are invalid")], render_kw={})

    recaptcha = RecaptchaField()

    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    """
    App Login Form
    """
    username = EmailField(validators=[InputRequired(), Email(
        granular_message=True, check_deliverability=True)], render_kw={"placeholder": "Email"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=8, max=100)], render_kw={})

    recaptcha = RecaptchaField()

    submit = SubmitField("Login")


class TelePhoneForm(FlaskForm):
    """
    Telegram Phone Number Form
    """
    phone = StringField(validators=[InputRequired(message="Empty field"), Length(
        min=11, max=11), Regexp("\+65(9|8)\d{7}", message="Only accepts +65XXXXXXXX")], render_kw={})

    submit = SubmitField("Next")


class TeleCodeForm(FlaskForm):
    """
    Telegram Login Code Form
    """
    code = IntegerField(validators=[InputRequired(
        message="Empty field"), NumberRange(min=10000, max=99999, message="Only five digits allowed")], render_kw={})

    submit = SubmitField("Next")


class Tele2faForm(FlaskForm):
    """
    Telgram 2FA Form
    """
    password = PasswordField(validators=[InputRequired(
        "Empty field"), Length(max=30)], render_kw={})

    submit = SubmitField("Login")


# Credentials from my.telegram.org
API_ID = os.environ["TELE_API_ID"]
API_HASH = os.environ["TELE_API_HASH"]


def parse_phone(phone):
    """Parses the given phone, or returns `None` if it's invalid."""
    if isinstance(phone, int):
        return str(phone)
    else:
        phone = sub(r'[+()\s-]', '', str(phone))
        if phone.isdigit():
            return phone


async def clear_tele_sessionkeys():
    """
    Clears all session keys starting with 'tele_',
    denoting that it is used for the telegram related routes
    """
    keylist = list(session.keys())
    for key in keylist:
        # pop only telegram related session keys (starts with tele_)
        if key.startswith('tele_'):
            session.pop(key)


@app.route('/register', methods=['GET', 'POST'])
async def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        app.logger.info("New user '%s' registered", form.username.data)
        return redirect(url_for('login'))

    return render_template("app-register.html", form=form)


@app.route('/email-verification', methods=['GET', 'POST'])
@login_required
async def email_verification():
    """
    For verification of email account.
    Route only accessible if email not verified (checked through current_user.email_verified)
    """
    if current_user.email_verified:
        return redirect(url_for("tele_login"))

    form = EmailVerificationForm()

    if request.method == "GET":
        # control code refresh frequency, only refresh code if past expiry time
        if current_user.email_code_creation:
            if ((current_user.email_code_creation + timedelta(minutes=30)).replace(tzinfo=timezone.utc)) >= datetime.now(timezone.utc):
                return render_template("app-verification.html", form=form)
        # update the database with a new code and created time

        new_code = ''.join(random.choices(CODE_CHARS, k=8))
        new_code_time = datetime.now(timezone.utc)

        upd_code = User.query.get_or_404(current_user.id)
        upd_code.email_code = bcrypt.generate_password_hash(new_code)
        upd_code.email_code_creation = new_code_time

        db.session.commit()

        # send verification code to email(from current_user)
        email_text = f"""
        Hi {current_user.username.split("@")[0]},

        Please ignore this email if you did not request for a verification code.

        Verification code: {new_code}
        Expires: 30 min or when new code is requested

        Best regards,
        Thambolo
        """
        recipients = [current_user.username]
        msg = MIMEText(email_text)
        msg["Subject"] = "Verification Code for Telegram-code-forwarder"
        msg["To"] = ", ".join(recipients)
        msg["From"] = GMAIL_USERNAME

        smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        smtp_server.login(GMAIL_USERNAME, GMAIL_APP_PASSWORD)
        try:
            smtp_server.sendmail(msg["From"], recipients, msg.as_string())
        finally:
            smtp_server.quit()

    if request.method == "POST":
        if form.validate_on_submit():

            # check the form code with the database code and expiry(created time + time till expiry)
            if current_user.email_code and current_user.email_code_creation:

                if ((current_user.email_code_creation + timedelta(minutes=30)).replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)):

                    flash(
                        message="Entered expired code, page has been refreshed to send a new code", category="Info")
                    app.logger.info(
                        "User '%s' entered an expired code, attempting to refresh to send a new code", current_user.username)

                    return redirect(url_for("email_verification"))

                # match: update database email_verified to True, nullify email_code and email_code_creation
                if bcrypt.check_password_hash(current_user.email_code, form.code.data):

                    upd_user = User.query.get_or_404(current_user.id)
                    upd_user.email_code = None
                    upd_user.email_code_creation = None
                    upd_user.email_verified = True

                    db.session.commit()

                    flash(message="Account verified", category="Info")
                    app.logger.info(
                        "User '%s' successfully verified their account", current_user.username)

                    return redirect(url_for("tele_login"))

                # no match: nullify email_code and email_code_creation, refresh page to retry
                else:

                    # upd_user = User.query.get_or_404(current_user.id)
                    # upd_user.email_code = None
                    # upd_user.email_code_creation = None

                    # db.session.commit()

                    flash(
                        message="Incorrect email verification code", category="Info")
                    app.logger.info(
                        "User '%s' entered an incorrect email verification code", current_user.username)

                    return redirect(url_for('email_verification'))

            app.logger.error(
                "User '%s's email_code and/or email_code_creation is not available in the database", current_user.username)
            return redirect(url_for('email_verification'))

    return render_template("app-verification.html", form=form)

# @app.route('/update-username', methods=['GET', 'POST'])
# async def update_username():
#     """
#     Update username (email)
#     """
#     form = ForgotPasswordForm()

#     # if request.method == "POST":

#     # if form.validate_on_submit():

#     return render_template('app-forgot-password.html', form=form)


@app.route('/forgot-password', methods=['GET', 'POST'])
async def forgot_password():
    """
    Forgot Password Page and Email form
    """
    email_form = ForgotPasswordEmailForm()
    update_form = ForgotPasswordUpdateForm()

    if request.method == "POST":

        if email_form.validate_on_submit():

            upd_code = db.session.execute(db.select(User).filter_by(
                username=email_form.username.data)).scalar_one_or_none()

            if upd_code:
                # generate code
                new_code = ''.join(random.choices(CODE_CHARS, k=8))
                new_code_time = datetime.now(timezone.utc)

                # store code data in db
                upd_code.forgot_password_code = bcrypt.generate_password_hash(
                    new_code)
                upd_code.forgot_password_code_creation = new_code_time

                db.session.commit()

                # send email with code
                email_text = f"""
                Hi {email_form.username.data.split("@")[0]},

                Please ignore this email if you did not request for a password change.

                Verification code: {new_code}

                Best regards,
                Thambolo
                """
                recipients = [email_form.username.data]
                msg = MIMEText(email_text)
                msg["Subject"] = "Password Change Verification Code for Telegram-code-forwarder"
                msg["To"] = ", ".join(recipients)
                msg["From"] = GMAIL_USERNAME

                smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
                smtp_server.login(GMAIL_USERNAME, GMAIL_APP_PASSWORD)
                try:
                    smtp_server.sendmail(
                        msg["From"], recipients, msg.as_string())
                finally:
                    smtp_server.quit()

                # log/flash successful
                app.logger.info(
                    "Successfully created code and sent email")

                return render_template('app-forgot-password.html', email_form=email_form, update_form=update_form, email_sent=True)

            # log/flash failure
            flash(
                message="User not found", category="Info")
            app.logger.info(
                "User '%s' not found", email_form.username.data)

            return redirect(url_for("forgot_password"))

    return render_template('app-forgot-password.html', email_form=email_form, update_form=update_form, email_sent=False)


@app.route('/forgot-password-update/<email>', methods=['POST'])
async def forgot_password_update(email):
    """
    Forgot Password Page and Email form
    """
    email_form = ForgotPasswordEmailForm()
    update_form = ForgotPasswordUpdateForm()

    if request.method == "POST":

        if update_form.validate_on_submit():

            # Update password in database
            upd_pw = db.session.execute(db.select(User).filter_by(
                username=email)).scalar_one_or_none()

            redirect_string = "login"

            if upd_pw:

                if bcrypt.check_password_hash(upd_pw.forgot_password_code, update_form.code.data):

                    hashed_password = bcrypt.generate_password_hash(
                        update_form.password.data)
                    upd_pw.password = hashed_password

                    # log
                    flash(
                        message="Password updated", category="Info")
                    app.logger.info(
                        "User successfully updated their password")
                    redirect_string = "login"
                else:
                    # log
                    flash(
                        message=f"Code Invalid '{update_form.code.data}'", category="Error")
                    app.logger.info(
                        "Incorrect code '%s'", update_form.code.data)
                    redirect_string = "forgot_password"
            else:
                # log
                flash(
                    message="Invalid user", category="Error")
                app.logger.info(
                    "Account %s not found", update_form.username.data)
                redirect_string = "forgot_password"

            # Nullify forgot_password_code and forgot_password_code_creation
            upd_pw.forgot_password_code = None
            upd_pw.forgot_password_code_creation = None

            db.session.commit()

            return redirect(url_for(redirect_string))

    return render_template('app-forgot-password.html', email_form=email_form, update_form=update_form)


@app.route('/login', methods=['GET', 'POST'])
async def login():
    form = LoginForm()

    if request.method == "POST":

        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    app.logger.info("User '%s' logged in", form.username.data)

                    if not user.email_verified:
                        app.logger.info(
                            "User '%s' email not verified", form.username.data)
                        return redirect(url_for("email_verification"))

                    return redirect(url_for('tele_login'))

    return render_template('app-login.html', form=form)


@app.route("/logout")
@login_required
async def logout():

    tmp_username = current_user.username

    keylist = list(session.keys())
    for key in keylist:
        if not key.startswith('_'):  # pop only non-flask_login session keys
            session.pop(key)

    # telethon disconnect from telegram (prevent sqlite3.OperationalError:database is locked)
    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}', API_ID, API_HASH)

    if not client.is_connected():
        await client.connect()

    await client.disconnect()

    # flask-login logout function
    logout_user()
    app.logger.info("User '%s' logged out", tmp_username)
    return redirect(url_for('login'))


@app.route("/", methods=["GET", "POST"])
@login_required
@require_account_verified
async def tele_login():
    """ 
    Essential for telethon's Asyncio to work with flask's threads. 
    Solution found at: https://github.com/LonamiWebs/Telethon/issues/1208
    """
    # loop = asyncio.new_event_loop()
    # asyncio.set_event_loop(loop)

    form = TelePhoneForm()

    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}', API_ID, API_HASH)

    # Connect to Telegram
    try:
        if not client.is_connected():
            await client.connect()
    except OperationalError:

        flash(message="There is a Telegram session in use in this account, terminate it to solve issues",
              category="Warning")

        app.logger.warning(
            "There is a Telegram session in use in this account, terminate it to solve issues")
        return redirect(url_for("tele_login"))

    # Check if already logged in
    me = await client.get_me()
    if me is not None:

        await client.disconnect()

        app.logger.info("User '%s' is already logged in",
                        current_user.username)
        return redirect(url_for("retrieve_code"))

    if request.method == "POST":

        if form.validate_on_submit():

            phone = form.phone.data

            # General check. The warnings here are on a best-effort and may fail.
            me = await client.get_me()
            if (me is not None) and (parse_phone(phone) != me.phone):
                # The warnings here are on a best-effort and may fail.
                await client.disconnect()

                # Not logged in, no code sent
                flash(message="The logged in Telegram account\'s phone number differs from the one received, terminate the session to use a new number",
                      category="Warning")
                app.logger.warning(
                    "User '%s' entered a phone number different from the one in their TelegramClient, they should terminate the session to use a new number", current_user.username)
                return redirect(url_for("tele_login"))

            else:

                # Send telegram code
                try:
                    sendcode = await client.send_code_request(phone, force_sms=False)

                except errors.PhonePasswordFloodError:
                    flash(message="Too many login attempt failures, floodwaited",
                          category="Error")
                    app.logger.error(
                        "User '%s' is being floodwaited for too many login attempts", current_user.username)
                    return redirect(url_for("tele_logout"))

                # Store info in session
                session['tele_phone'] = phone
                session['tele_phone_code_hash'] = sendcode.phone_code_hash

                await client.disconnect()

                app.logger.info(
                    "User '%s' successfully passed the Telegram phone form", current_user.username)
                return redirect(url_for("code"))

    return render_template("tele-login.html", form=form)

# Retrieve telegram code from user


@app.route("/code", methods=["GET", "POST"])
@login_required
@require_account_verified
async def code():

    # redirect to phone form if no tele_phone session key
    if "tele_phone" not in session:
        app.logger.warning(
            "User '%s' tried to access Telegram login code form without first completing Telegram phone form", current_user.username)
        return redirect(url_for("tele_login"))

    form = TeleCodeForm()

    if request.method == "POST":

        if form.validate_on_submit():

            # Set the Client session to be used based on current user logged in
            client = TelegramClient(
                f'{THIS_FOLDER}/tele_sessions/{current_user.id}', API_ID, API_HASH)

            # Connect to Telegram if not connected
            if not client.is_connected():
                await client.connect()

            if "tele_code_max_attempt_expiry" in session:
                if (session['tele_code_max_attempt_expiry'] <= datetime.now(timezone.utc)):
                    session.pop("tele_code_attempts")
                    session.pop("tele_code_max_attempt_expiry")

            if "tele_code_attempts" not in session:
                session['tele_code_attempts'] = 0

            phone = session['tele_phone']
            max_attempts = 3
            two_step_detected = False

            # Validate telegram code from client
            while (int(session["tele_code_attempts"]) < max_attempts):
                try:
                    # I NEED TO SELF DEFINE THE WAY IT GETS THE CODE FROM USER HERE
                    code_given = form.code.data

                    # Raises SessionPasswordNeededError if 2FA enabled
                    await client.sign_in(phone, code=code_given, phone_code_hash=session['tele_phone_code_hash'])
                    break
                except errors.SessionPasswordNeededError:
                    two_step_detected = True
                    session['tele_2FA'] = two_step_detected
                    break
                except (errors.PhoneCodeEmptyError,
                        errors.PhoneCodeExpiredError,
                        errors.PhoneCodeHashEmptyError,
                        errors.PhoneCodeInvalidError):
                    flash(message="Invalid code, try again",
                          category="Warning")
                    app.logger.warning(
                        "User '%s' entered an invalid Telegram login code", current_user.username)
                    return redirect(url_for("code"))

                finally:
                    session["tele_code_attempts"] += 1

            else:

                if 'tele_code_max_attempt_expiry' not in session:
                    session['tele_code_max_attempt_expiry'] = datetime.now(
                        timezone.utc) + timedelta(seconds=60)

                await client.disconnect()

                flash(message=f'{max_attempts} consecutive sign-in attempts failed, wait 60 seconds to try again',
                      category="Error")
                app.logger.warning(
                    "User '%s' has %s consecutive sign-in attempts failed, wait 60 seconds to try again", current_user.username, str(max_attempts))
                return redirect(url_for("code"))

            # Clear attempts (since if code reached here, means it passed)
            session.pop("tele_code_attempts")

            if two_step_detected:
                await client.disconnect()

                app.logger.info(
                    "User '%s' successfully passed Telegram login code form", current_user.username)
                return redirect(url_for("get2FA"))
            else:
                me = await client.get_me()
                session["tele_user"] = me.username

                app.logger.info(
                    "User '%s' successfully logged into Telegram account '%s'", current_user.username, me.username)

                await client.disconnect()
                await clear_tele_sessionkeys()

                return redirect(url_for("retrieve_code"))

    return render_template("tele-login-code.html", form=form, phone=session["tele_phone"])


# Retrieve telegram 2FA from user when called


@app.route("/2fa", methods=["GET", "POST"])
@login_required
@require_account_verified
async def get2FA():

    if "tele_2FA" not in session:

        app.logger.info(
            "User '%s' tried to access Telegram 2FA form without first completing Telegram login code form", current_user.username)
        return redirect(url_for("code"))

    form = Tele2faForm()

    if request.method == "POST":

        # Check if maxed attempts
        if "tele_2FA_remaining_attempts" in session:
            if session["tele_2FA_remaining_attempts"] == 0:

                app.logger.warning(
                    "User '%s' has reached maximum of 3 2FA attempts", current_user.username)
                return redirect(url_for("tele_logout"))

        if form.validate_on_submit():

            two_step_detected = session['tele_2FA']
            password = form.password.data

            client = TelegramClient(
                f'{THIS_FOLDER}/tele_sessions/{current_user.id}', API_ID, API_HASH)

            # Connect to Telegram
            if not client.is_connected():
                await client.connect()

            # initialise attempts remaining on first invocation only
            if "tele_2FA_remaining_attempts" not in session:
                session["tele_2FA_remaining_attempts"] = 3

            me = None
            phone = session['tele_phone']

            # Validate 2FA if 2FA is requested
            if two_step_detected:

                try:
                    me = await client.sign_in(phone=phone, password=password)

                except errors.PasswordHashInvalidError:
                    session["tele_2FA_remaining_attempts"] -= 1

                    # if session["tele_2FA_remaining_attempts"] == 0:
                    #     return redirect(url_for("tele_logout"))

                    flash(message="Invalid password, try again",
                          category="Warning")
                    app.logger.info(
                        "User '%s' entered invalid 2FA password and has %s remaining 2FA attempts", current_user.username, session["tele_2FA_remaining_attempts"])
                    return render_template("tele-login-2fa.html", form=form)

                except errors.rpcerrorlist.FloodWaitError as err:

                    flash(message=f"Too many login failures, wait for {err.seconds} seconds to try again",
                          category="Warning")

                    app.logger.warning(
                        "User '%s' has too many 2FA password failures, wait for %s seconds to try again", current_user.username, str(err.seconds))
                    return redirect(url_for("tele_logout"))

            # We won't reach here if any step failed (exit by exception)
            # Success!
            session.pop("tele_2FA_remaining_attempts")

            if "tele_user" not in session:
                session["tele_user"] = me.username

            await client.disconnect()

            app.logger.info(
                "User '%s' successfully logged into Telegram account '%s'", current_user.username, me.username)

            await clear_tele_sessionkeys()

            return redirect(url_for("retrieve_code"))

    return render_template("tele-login-2fa.html", form=form)


@app.route("/retrieve-code", methods=["GET"])
@login_required
@require_account_verified
async def retrieve_code():

    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}', API_ID, API_HASH)

    # Connect to Telegram
    if not client.is_connected():
        await client.connect()

    # only allow access to this route if logged in on telegram
    if not await client.is_user_authorized():
        await client.disconnect()

        return redirect(url_for("tele_login"))

    await client.disconnect()

    return render_template("retrieve-code.html", )


@app.route("/retrieve-code-btn", methods=["GET"])
@login_required
@require_account_verified
async def retrieve_code_btn():
    # gets the last < 3 login codes
    # track how many times user is activating this route using session dict. maximum should be 6 invocations every 30sec.
    if 'tele_retrieve_code_invoke_expiry' in session:
        current_time = datetime.now(timezone.utc)
        if (current_time < session['tele_retrieve_code_invoke_expiry']) and (session['tele_retrieve_code_invocations'] >= 6):
            app.logger.warning(
                "User '%s' exceeded rate-limit of 6 per 30s, wait before polling again", current_user.username)
            return {"codes": [], "message": "Exceeded rate-limit of 6 per 30s, wait before polling again"}, 429

        # reset expiry and invoke count if expired (30s from 1st invocation)
        if (current_time >= session['tele_retrieve_code_invoke_expiry']):
            session.pop("tele_retrieve_code_invoke_expiry")
            session.pop("tele_retrieve_code_invocations")
    #################################################################################
    # TELETHON get login codes
    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}', API_ID, API_HASH)

    # Connect to Telegram
    if not client.is_connected():
        await client.connect()

    # Get entity for id 777000(telegram)
    tele_chat_entity = await client.get_input_entity(777000)

    codes = []
    # Get login codes. Every call will get the latest 3 login codes out in the past N messages from Telegram.
    async for message in client.iter_messages(tele_chat_entity, from_user=tele_chat_entity, limit=15):
        # check if message has login code
        code_match = search(
            "(?is)(?<=login\scode:\s)\d{5}?(?=\.)", message.message)

        if code_match is not None:
            code = code_match.group()
            codes.append({"code": code, "timestamp": message.date})

        # collected 3 codes, break out of loop
        if len(codes) == 3:
            break

    # failure in regex or no codes exist
    if len(codes) == 0:
        res_msg = "No login codes found"
    else:
        res_msg = "Login code(s) updated"

    ##################################################################################
    # save datetime expiry and increment invocation count if invoked SUCCESSFULLY
    if 'tele_retrieve_code_invocations' not in session:
        session['tele_retrieve_code_invocations'] = 1
    else:
        session['tele_retrieve_code_invocations'] += 1

    if 'tele_retrieve_code_invoke_expiry' not in session:
        session['tele_retrieve_code_invoke_expiry'] = datetime.now(
            timezone.utc) + timedelta(seconds=31)

    client.disconnect()

    return {"codes": codes, "message": res_msg}, 200
    # return {"codes": [{"code": 12345, "timestamp": datetime.now()}, {"code": 54321, "timestamp": datetime.now()}], "message": "No login codes found"}, 200
    # return {"codes": [], "message": "No login codes found"}, 200


@app.route("/tele-logout", methods=["GET"])
@login_required
@require_account_verified
async def tele_logout():

    await clear_tele_sessionkeys()

    # Connect to Telegram
    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}', API_ID, API_HASH)

    if not client.is_connected():
        await client.connect()

    await client.log_out()

    app.logger.info(
        "User '%s' logged-out/terminated their Telegram session", current_user.username)
    return redirect(url_for("tele_login"))


@app.errorhandler(500)
def internal_server_error(e):
    # note that we set the 500 status explicitly
    return render_template('error.html', svgName="sardine", statuscode=500, title="Internal Server Error", msg="Oops... we made a mistake, sorry!"), 500


@app.errorhandler(404)
def not_found_error(e):
    # note that we set the 404 status explicitly
    return render_template('error.html', svgName="starfish", statuscode=404, title="Not Found", msg="You entered the wrong address"), 404


@app.errorhandler(OperationalError)
async def telethon_database_locked(e):

    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}', API_ID, API_HASH)

    if client.is_connected():
        await client.disconnect()

    return redirect(location=request.path)
