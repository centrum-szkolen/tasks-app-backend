from flask import Flask, jsonify, request,session
from werkzeug.security import generate_password_hash, check_password_hash
from config import users_collection
from utils.regex_patterns import password_pattern, email_pattern
from utils.session_expiration import set_session_expiration
from dotenv import load_dotenv
from utils.get_response import get_response
from flask_cors import CORS
import datetime
import re
import os 
load_dotenv()

app = Flask(__name__)

cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

app.secret_key = os.getenv("SECRET_KEY")

# ---------------------------------------------------------------------------------------------------------
# Rejestracja użytkownika
@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']
        email = request.json['email']
        hashed_password = generate_password_hash(password)

        if users_collection.find_one({'username': username}):
            return get_response('Użytkownik o podanej nazwie już istnieje',False,500)

        # Sprawdzenie czy email istnieje już w bazie
        if users_collection.find_one({'email': email}):
            return get_response('Konto o podanym adresie email już istnieje',False,500)

        # Sprawdzenie hasła za pomocą regular expression
        if re.match(password_pattern, password) is None:
            return get_response('Hasło musi zawierać małą, dużą literę, cyfrę i minimum 5 znaków',False,500)
        
        # Sprawdzenie emaila za pomocą regular expression
        if re.match(email_pattern, email) is None:
            return get_response('Niepoprawny adres email',False,500)

        # Dodanie nowego dokumentu do bazy
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'email': email
        })

        # Wyświetlenie czegoś po pomyślnym wyślaniu zapytania o rejestrację
        new_user = {
            'username': username,
            'password': hashed_password,
            'email': email
        }
        return get_response("Utworzono konto",True,201,new_user)

#-------------------------------------------------------------------------------
# Logowanie
@app.route('/login',methods=['POST'])
def login():
     password = request.json['password']
     email = request.json['email']

     user = users_collection.find_one({'email':email})

     if user and check_password_hash(user['password'], password):
         expiration = set_session_expiration(app)
         session['email'] = user['email']
         session['date'] = (datetime.datetime.now() + expiration).strftime('%H:%M:%S')

         return get_response('Poprawnie zalogowano',True,200)
     
     return get_response('Błędny email lub hasło',False,403)


# -----------------------------------------------------------------------------------------------
# Panel użytkownika
@app.route('/dashboard',methods=['GET'])
def dashboard():
    if 'email' in session:
        user = users_collection.find_one({'email':session['email']})
        return get_response('Zalogowano jako ' + user['username'],True,200)
    else:
     return get_response('Odmowa dostępu',False,403)
    

# Wylogowanie
@app.route('/logout')
def logout():

    session.pop('email',None)
    session.pop('date',None)
    return get_response('Pomyślnie wylogowano',True,200)


# Wyświetlanie wszystkich userów
@app.route('/get-users')
def get_users():
    users = users_collection.find({},{'_id':0})
    return jsonify(list(users))