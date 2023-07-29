from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash
from config import users_collection
from utils.regex_patterns import password_pattern, email_pattern
import re

app = Flask(__name__)


# Rejestracja użytkownika
@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']
        email = request.json['email']
        hashed_password = generate_password_hash(password)

        if users_collection.find_one({'username': username}):
            error_response = jsonify({
                'message': 'Użytkownik o podanej nazwie już istnieje',
                'ok': False,
                'status': 500
            })
            error_response.status_code = 500
            return error_response

        # Sprawdzenie czy email istnieje już w bazie
        if users_collection.find_one({'email': email}):
            error_response = jsonify({
                'message': 'Konto o podanym adresie email już istnieje',
                'ok': False,
                'status': 500
            })
            error_response.status_code = 500
            return error_response

        # Sprawdzenie hasła za pomocą regular expression
        if re.match(password_pattern, password) is None:
            error_response = jsonify({
                'message': 'Hasło musi zawierać małą, dużą literę, cyfrę i minimum 5 znaków',
                'ok': False,
                'status': 500
            })
            error_response.status_code = 500
            return error_response
        
        # Sprawdzenie emaila za pomocą regular expression
        if re.match(email_pattern, email) is None:
            error_response = jsonify({
                'message': 'Niepoprawny adres email',
                'ok': False,
                'status': 500
            })
            error_response.status_code = 500
            return error_response

        # Dodanie nowego dokumentu do bazy
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'email': email
        })

        # Wyświetlenie czegoś po pomyślnym wyślaniu zapytania o rejestrację
        response = jsonify({
            'username': username,
            'password': hashed_password,
            'email': email
        })
        response.status_code = 201

        return response
