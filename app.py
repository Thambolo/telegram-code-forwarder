# import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
import os
from re import sub, search
from sqlite3 import OperationalError
from flask import Flask, redirect, render_template, request, session, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from telethon import TelegramClient, errors
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo, Regexp, NumberRange
from flask_bcrypt import Bcrypt
from markupsafe import escape

from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env

# Init
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

# Path init
THIS_FOLDER = Path(__file__).parent.resolve()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20), Regexp("^[a-zA-Z0-9]*$", message="Only accepts alphanumeric values")], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20), EqualTo('password2', message='Passwords must match')], render_kw={"placeholder": "Password"})

    password2 = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Confirm Password"})

    recaptcha = RecaptchaField()

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_username = User.query.filter_by(
            username=username.data).first()
        if existing_username:
            self.username.errors += (ValidationError(
                "That username already exists. Choose a different one."),)


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(message="Username must not be empty"), Length(
        min=4, max=20), Regexp("^[a-zA-Z0-9]*$", message="Only accepts alphanumeric values")], render_kw={})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={})

    recaptcha = RecaptchaField()

    submit = SubmitField("Login")


class TelePhoneForm(FlaskForm):
    phone = StringField(validators=[InputRequired(message="Empty field"), Length(
        min=11, max=11), Regexp("\+65(9|8)\d{7}", message="Only accepts +65XXXXXXXX")], render_kw={})

    submit = SubmitField("Next")


class TeleCodeForm(FlaskForm):
    code = IntegerField(validators=[InputRequired(
        message="Empty field"), NumberRange(min=10000, max=99999, message="Only five digits allowed")], render_kw={})

    submit = SubmitField("Next")


class Tele2faForm(FlaskForm):
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
        return redirect(url_for('login'))

    return render_template("app-register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
async def login():

    form = LoginForm()
    if request.method == "POST":

        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('tele_login'))

    return render_template('app-login.html', form=form)


@app.route("/logout")
@login_required
async def logout():
    keylist = list(session.keys())
    for key in keylist:
        if not key.startswith('_'):  # pop only non-flask_login session keys
            session.pop(key)

    # flask-login logout function
    logout_user()
    return redirect(url_for('login'))


@app.route("/", methods=["GET", "POST"])
@login_required
async def tele_login():
    """ 
    Essential for telethon's Asyncio to work with flask's threads. 
    Solution found at: https://github.com/LonamiWebs/Telethon/issues/1208
    """
    # loop = asyncio.new_event_loop()
    # asyncio.set_event_loop(loop)

    form = TelePhoneForm()

    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}_{current_user.username}', API_ID, API_HASH)

    # Connect to Telegram
    try:
        if not client.is_connected():
            await client.connect()
    except OperationalError:

        flash(message="There is a Telegram session in use in this account, terminate it to solve issues",
              category="Warning")
        return redirect(url_for("tele_login"))

    # Check if already logged in
    me = await client.get_me()
    if me is not None:

        await client.disconnect()

        # already logged in, no code sent
        # flash(message="Already logged in",
        #       category="Info")

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
                flash(message="The logged in session\'s phone number differs from the one received, terminate the session to use a new number",
                      category="Warning")
                return redirect(url_for("tele_login"))

            else:

                # Send telegram code
                try:
                    sendcode = await client.send_code_request(phone, force_sms=False)

                except errors.PhonePasswordFloodError:
                    flash(message="Too many login attempt failures, floodwaited",
                          category="Error")

                    return redirect(url_for("tele_logout"))

                # Store info in session
                session['tele_phone'] = phone
                session['tele_phone_code_hash'] = sendcode.phone_code_hash

                await client.disconnect()

                # print(session)

                return redirect(url_for("code"))

    return render_template("tele-login.html", form=form)

# Retrieve telegram code from user


@app.route("/code", methods=["GET", "POST"])
@login_required
async def code():

    # redirect to phone form if no tele_phone session key
    if "tele_phone" not in session:
        return redirect(url_for("tele_login"))

    form = TeleCodeForm()

    if request.method == "POST":

        if form.validate_on_submit():

            # Set the Client session to be used based on current user logged in
            client = TelegramClient(
                f'{THIS_FOLDER}/tele_sessions/{current_user.id}_{current_user.username}', API_ID, API_HASH)

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
                return redirect(url_for("code"))

            # Clear attempts (since if code reached here, means it passed)
            session.pop("tele_code_attempts")

            # print(session)

            if two_step_detected:
                await client.disconnect()

                return redirect(url_for("get2FA"))
            else:
                me = await client.get_me()
                session["tele_user"] = me.username
                await client.disconnect()
                await clear_tele_sessionkeys()

                return redirect(url_for("retrieve_code"))

    return render_template("tele-login-code.html", form=form, phone=session["tele_phone"])


# Retrieve telegram 2FA from user when called


@app.route("/2fa", methods=["GET", "POST"])
@login_required
async def get2FA():

    if "tele_2FA" not in session:
        return redirect(url_for("code"))

    form = Tele2faForm()

    if request.method == "POST":

        # Check if maxed attempts
        if "tele_2FA_remaining_attempts" in session:
            if session["tele_2FA_remaining_attempts"] == 0:
                return redirect(url_for("tele_logout"))

        if form.validate_on_submit():

            two_step_detected = session['tele_2FA']
            password = form.password.data

            client = TelegramClient(
                f'{THIS_FOLDER}/tele_sessions/{current_user.id}_{current_user.username}', API_ID, API_HASH)

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

                    if session["tele_2FA_remaining_attempts"] == 0:
                        return redirect(url_for("tele_logout"))

                    flash(message="Invalid password, try again",
                          category="Warning")

                    return render_template("tele-login-2fa.html", form=form)

                except errors.rpcerrorlist.FloodWaitError as err:

                    flash(message=f"Too many login failures, wait for {err.seconds} seconds to try again",
                          category="Warning")

                    return redirect(url_for("tele_logout"))

            # We won't reach here if any step failed (exit by exception)
            # Success!
            session.pop("tele_2FA_remaining_attempts")

            if "tele_user" not in session:
                session["tele_user"] = me.username

            await clear_tele_sessionkeys()

            await client.disconnect()

            return redirect(url_for("retrieve_code"))

    return render_template("tele-login-2fa.html", form=form)


@app.route("/retrieve-code", methods=["GET"])
@login_required
async def retrieve_code():

    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}_{current_user.username}', API_ID, API_HASH)

    # Connect to Telegram
    if not client.is_connected():
        await client.connect()

    # only allow access to this route if logged in on telegram
    if not await client.is_user_authorized():
        return redirect(url_for("tele_login"))

    return render_template("retrieve-code.html", )


@app.route("/retrieve-code-btn", methods=["GET"])
@login_required
async def retrieve_code_btn():
    # gets the last < 3 login codes
    # track how many times user is activating this route using session dict. maximum should be 6 invocations every 30sec.
    if 'tele_retrieve_code_invoke_expiry' in session:
        current_time = datetime.now(timezone.utc)
        if (current_time < session['tele_retrieve_code_invoke_expiry']) and (session['tele_retrieve_code_invocations'] >= 6):
            return {"codes": [], "message": "Exceeded rate-limit of 6 per 30s, wait before polling again"}, 429

        # reset expiry and invoke count if expired (30s from 1st invocation)
        if (current_time >= session['tele_retrieve_code_invoke_expiry']):
            session.pop("tele_retrieve_code_invoke_expiry")
            session.pop("tele_retrieve_code_invocations")
    #################################################################################
    # TELETHON get login codes
    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}_{current_user.username}', API_ID, API_HASH)

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
async def tele_logout():

    await clear_tele_sessionkeys()

    # Connect to Telegram
    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}_{current_user.username}', API_ID, API_HASH)

    if not client.is_connected():
        await client.connect()

    await client.log_out()

    return redirect(url_for("tele_login"))
