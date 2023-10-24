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
4. environment variables should be added in the file .env (all required vars below)
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
5. Run Flask in dev mode using (vscode terminal):
`flask run --debug`
