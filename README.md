# telegram-code-forwarder
 Forwards telegram's login code to the browser instead of your mobile
 
## Built on
- Flask
- Tailwindcss
- Sqlite3

## set-up
1. Recommended to use python's virtual environment "venv"
2. Activate the virtual environment
3. pip install all the dependencies in requirements.txt
4. environment variables should be added in the file .env in project root (all required vars below)
```
# Google recaptcha v2 keys
RECAPTCHA_PUBLIC_KEY=
RECAPTCHA_PRIVATE_KEY=
# Strong random string of characters
APP_SECRET_KEY=
# From my.telegram.org
TELE_API_HASH=
TELE_API_ID=
```
5. Create the user db using the user class defined in app.py (Or drop in the db if I sent u):
```
# looks like that. Check out flask sqlalchemy on how to create a db from this.
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
```
6. Ensure db is in instance/ directory (you might have to create dir)
7. Run Flask in dev mode using (vscode terminal):
```flask run --debug```
8. Additionally, open another terminal and run this line for updates to tailwind to work:
```npx tailwindcss -i ./static/src/input.css -o ./static/dist/css/output.css --watch```
