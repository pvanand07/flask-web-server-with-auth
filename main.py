
from flask import Flask, render_template, request, jsonify, make_response
from flask_cors import CORS
from supabase import create_client
from jose import jwt
import os
from datetime import datetime, timedelta
import logging

app = Flask(__name__)
CORS(app)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Configuration variables (use environment variables in production)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

# URL variables
APP_URL = 'https://www.app.com'
WAITLIST_URL = 'https://www.waitlist.com'
LOGIN_URL = 'https://www.login.com'

# Initialize Supabase client
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def create_jwt(payload):
    exp = datetime.utcnow() + timedelta(hours=24)
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256', headers={'exp': exp})

def verify_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except:
        return None

@app.route('/')
def index():
    app.logger.debug("Rendering index.html")
    return render_template('index.html')

@app.route('/check_status', methods=['POST'])
def check_status():
    app.logger.debug("Received request to /check_status")
    token = request.json.get('token')
    app.logger.debug(f"Received token: {token}")
    
    if not token:
        app.logger.debug("No token provided, redirecting to login")
        return jsonify({'url': LOGIN_URL})

    jwt_payload = verify_jwt(token)
    if jwt_payload:
        app.logger.debug(f"Valid JWT payload: {jwt_payload}")
        if jwt_payload.get('authenticated') and jwt_payload.get('valid'):
            return jsonify({'url': APP_URL})
        elif jwt_payload.get('authenticated') and not jwt_payload.get('valid'):
            return jsonify({'url': WAITLIST_URL})
        else:
            return jsonify({'url': LOGIN_URL})

    try:
        user_email = jwt.decode(token, options={"verify_signature": False})['email']
        app.logger.debug(f"Decoded email from token: {user_email}")
    except:
        app.logger.debug("Failed to decode email from token")
        return jsonify({'url': LOGIN_URL})

    if not user_email:
        app.logger.debug("No email in token")
        return jsonify({'url': LOGIN_URL})

    app.logger.debug("Checking email in Supabase")
    response = supabase.table('email_allowlist').select('email').eq('email', user_email).execute()
    app.logger.debug(f"Supabase response: {response}")
    
    user_authenticated = True
    user_valid = len(response.data) > 0

    new_token = create_jwt({'authenticated': user_authenticated, 'valid': user_valid})
    app.logger.debug(f"Created new token: {new_token}")
    
    if user_authenticated and user_valid:
        url = APP_URL
    elif user_authenticated and not user_valid:
        url = WAITLIST_URL
    else:
        url = LOGIN_URL

    app.logger.debug(f"Redirecting to: {url}")
    resp = make_response(jsonify({'url': url, 'token': new_token}))
    resp.set_cookie('auth_token', new_token, httponly=True, secure=True, samesite='Strict', max_age=86400)
    return resp

if __name__ == '__main__':
    app.run(debug=True, port=7860)
