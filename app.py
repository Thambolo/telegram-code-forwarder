# import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
import os
from re import sub, search
from sqlite3 import OperationalError
from inspect import isawaitable
from flask import Flask, redirect, render_template, request, session, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from telethon import TelegramClient, errors
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo, Regexp
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


def phone_validated(phone):
    # escaping
    phone = escape(phone)

    # match Singapore phone format
    phone_match = search("\+65(9|8)\d{7}", phone)

    if phone_match is None:
        return False
    else:
        return True


def code_validated(code_given):

    if code_given is not None:
        # match 5 digit login code
        return len(str(code_given)) == 5

    return False


def password_validated(password):

    if (password is not None) and (password):
        return True

    return False


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

    if request.method == "POST":

        phone = request.form.get("phone")

        # phone number validation
        if not phone_validated(phone):
            return {"errors": ["Must follow the format +65XXXXXXXX"]}, 400

        # Activate telethon login process
        client = TelegramClient(
            f'{THIS_FOLDER}/tele_sessions/{current_user.id}_{current_user.username}', API_ID, API_HASH)

        # Connect to Telegram
        try:
            if not client.is_connected():
                await client.connect()
        except OperationalError:
            response = {
                'message': 'There is a Telegram session in use in this account, terminate it to solve issues.'
            }
            return response, 200

        # General check
        me = await client.get_me()
        if me is not None:
            # The warnings here are on a best-effort and may fail.
            if parse_phone(phone) != me.phone:
                await client.disconnect()

                return {'message': 'The logged in session\'s phone number differs from the one received, terminate the session to use a new number', 'code_sent': False, 'logged_in': False}, 200

            await client.disconnect()
            return {'message': 'Logged in', 'code_sent': False, 'logged_in': True}, 200
        else:
            # Validate phone number
            while callable(phone):
                value = phone()
                if isawaitable(value):
                    value = await value
                phone = parse_phone(value) or phone

            # Send telegram code
            sendcode = await client.send_code_request(phone, force_sms=False)

            # Store info in session
            session['tele_phone'] = phone
            session['tele_phone_code_hash'] = sendcode.phone_code_hash

            response = {
                'message': 'Login code has been sent',
                'code_sent': True,
                'logged_in': False,
            }
            await client.disconnect()
            return response, 200

    return render_template("tele-login.html")

# Retrieve telegram code from user


@app.route("/code", methods=["POST"])
@login_required
async def code():

    if request.method == "POST":

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
                code_given = request.form.get("code", type=int)

                # code format validation
                if not code_validated(code_given):
                    return {"errors": ["Invalid length"]}, 400

                if isawaitable(code_given):
                    code_given = await code_given

                # Since sign-in with no code works (it sends the code)
                # we must double-check that here. Else we'll assume we
                # logged in, and it will return None as the User.
                if not code_given:
                    # no code received
                    return {"message": "Invalid code, try again."}, 400

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
                return {"message": "Invalid code, try again."}, 400

            finally:
                session["tele_code_attempts"] += 1

        else:

            if 'tele_code_max_attempt_expiry' not in session:
                session['tele_code_max_attempt_expiry'] = datetime.now(
                    timezone.utc) + timedelta(seconds=60)

            client.disconnect()

            return {"message": f'{max_attempts} consecutive sign-in attempts failed, wait 60 seconds to try again'}, 400

        await client.disconnect()

        # Clear attempts (since if code reached here, means it passed)
        session.pop("tele_code_attempts")

        return {"two_step_detected": two_step_detected, "message": f'{"2FA required" if two_step_detected else "You are logged in!" }'}, 200


# Retrieve telegram 2FA from user when called


@app.route("/2fa", methods=["POST"])
@login_required
async def get2FA():

    two_step_detected = session['tele_2FA']
    password = request.form.get("2fa")

    if not password_validated(password):
        return {"errors": ["Password invalid"]}, 400

    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}_{current_user.username}', API_ID, API_HASH)

    # Connect to Telegram
    if not client.is_connected():
        await client.connect()

    max_attempts = 3
    me = None
    phone = session['tele_phone']

    # Validate 2FA if 2FA is requested
    if two_step_detected:

        if callable(password):
            for _ in range(max_attempts):
                try:
                    value = password()
                    if isawaitable(value):
                        value = await value

                    me = await client.sign_in(phone=phone, password=value)
                    break  # break will leave the loop, skips the else:

                except errors.PasswordHashInvalidError:
                    # return will leave the loop, skips the else:
                    return {"message": "Invalid password, try again."}, 200
            else:
                # Reaches here if max attempts reached
                return {"message": f'{max_attempts} consecutive password attempts failed'}, 200
        else:
            me = await client.sign_in(phone=phone, password=password)

    # We won't reach here if any step failed (exit by exception)
    # Success!
    signed, name = 'Signed in successfully as ', me.first_name
    tos = '; remember to not break the ToS or you will risk an account ban!'

    try:
        print(signed, name, tos, sep='')
    except UnicodeEncodeError:
        # Some terminals don't support certain characters
        print(signed, name.encode('utf-8', errors='ignore')
              .decode('ascii', errors='ignore'), tos, sep='')

    await client.disconnect()

    return {"message": "2FA successful, you are logged in"}, 200


@app.route("/retrieve-code", methods=["GET"])
@login_required
async def retrieve_code():

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

    keylist = list(session.keys())
    for key in keylist:
        # pop only telegram related session keys (starts with tele_)
        if key.startswith('tele_'):
            session.pop(key)

    # Connect to Telegram
    client = TelegramClient(
        f'{THIS_FOLDER}/tele_sessions/{current_user.id}_{current_user.username}', API_ID, API_HASH)

    if not client.is_connected():
        await client.connect()

    await client.log_out()

    return redirect(url_for("tele_login"))


@app.route("/test", methods=["GET", "POST"])
@login_required
async def test():
    if request.method == "POST":
        print(request.form.get("test"))

    print("TESSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSTTTTTTTTTTTTTTTTTT")

    return render_template("test.html")
