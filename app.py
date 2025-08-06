from flask import Flask, request, jsonify
from email_validator import validate_email, EmailNotValidError
import bcrypt
from firebase_admin import credentials, firestore, initialize_app
from firebase_admin.firestore import transactional
import re
import os
import jwt
from datetime import datetime, timedelta, timezone
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from google.cloud import secretmanager
from flask_cors import CORS
import json


_client = secretmanager.SecretManagerServiceClient()
_project_id = "news-467923" # or hard‐code your project test

def get_secret(secret_id: str, version: str = "latest") -> str:
    name = f"projects/{_project_id}/secrets/{secret_id}/versions/{version}"
    response = _client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8")

# JWT configuration
JWT_SECRET = get_secret("JWT_SECRET")
JWT_EXPIRES_IN = 86400  # seconds, default 15 minutes
JWT_ISSUER = "auth-service"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

firebase_cred_json = get_secret("firebaseCredentials")
firebase_cred = json.loads(firebase_cred_json)

cred = credentials.Certificate(firebase_cred)
initialize_app(cred)
db = firestore.client()
transaction = db.transaction()

app = Flask(__name__)
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True
)



def validate_username(username):
    """Username validation: 3-30 chars, alphanumeric and underscores only"""
    pattern = r'^[a-zA-Z0-9_]{3,30}$'
    return re.match(pattern, username) is not None

def validate_password(password):
    """Password validation: minimum 8 characters"""
    return len(password) >= 8

def issue_jwt(user_id, email, username):
    """Create an HS256 JWT for the authenticated user"""
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=JWT_EXPIRES_IN)
    payload = {
        'sub': user_id,
        'email': email,
        'username': username,
        'iat': int(now.timestamp()),
        'exp': int(exp.timestamp()),
        'iss': JWT_ISSUER,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def verify_google_id_token(id_token_str: str):
    """
    Verify Google ID token and return claims.
    Raises Exception if verification fails or email not verified or audience mismatch.
    """
    if not GOOGLE_CLIENT_ID:
        raise Exception("Server misconfiguration: GOOGLE_CLIENT_ID not set")

    request_adapter = google_requests.Request()
    claims = google_id_token.verify_oauth2_token(id_token_str, request_adapter, GOOGLE_CLIENT_ID)

    if claims.get("aud") != GOOGLE_CLIENT_ID:
        raise Exception("Invalid audience")
    if not claims.get("email"):
        raise Exception("Google token missing email")
    if not claims.get("email_verified", False):
        raise Exception("Email not verified")

    return claims

@transactional
def register_user(txn, data):
    email = data['email']
    username = data['username']
    
    email_ref    = db.collection('userEmails').document(email)
    user_ref     = db.collection('usernames').document(username)
    
    # 1. ensure uniqueness
    if email_ref.get(transaction=txn).exists:
        raise Exception("Email already taken")
    if user_ref.get(transaction=txn).exists:
        raise Exception("Username already taken")
        
    # 2. create user doc
    new_ref = db.collection('users').document()  # auto-ID
    txn.set(new_ref, {
        **data,
        'created_at': firestore.SERVER_TIMESTAMP,
    })
        
    # 3. create lookups
    txn.set(email_ref,    {'userId': new_ref.id})
    txn.set(user_ref,     {'userId': new_ref.id})
    
    return new_ref.id

@transactional
def register_google_user(txn, user_data, email, username):
    """
    Register a new Google user with transactional safety.
    Ensures username and email uniqueness atomically.
    """
    email_ref = db.collection('userEmails').document(email)
    username_ref = db.collection('usernames').document(username)
    
    # 1. ensure uniqueness within transaction
    if email_ref.get(transaction=txn).exists:
        raise Exception("Email already registered")
    if username_ref.get(transaction=txn).exists:
        raise Exception("Username already taken")
    
    # 2. create user doc
    new_user_ref = db.collection('users').document()  # auto-ID
    txn.set(new_user_ref, {
        **user_data,
        'created_at': firestore.SERVER_TIMESTAMP,
    })
    
    # 3. create lookups
    txn.set(email_ref, {'userId': new_user_ref.id})
    txn.set(username_ref, {'userId': new_user_ref.id})
    
    return new_user_ref.id

@app.route('/register', methods=['POST'])
def register():
    """Register a new user with email, username, and password"""
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        # Validate required fields
        if not email or not username or not password:
            return jsonify({'error': 'Email, username, and password are required'}), 400
        
        # Validate email format
        try:
            validate_email(email)
        except EmailNotValidError as e:
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate username format
        if not validate_username(username):
            return jsonify({'error': 'Username must be 3-30 characters, alphanumeric and underscores only'}), 400
        
        # Validate password strength
        if not validate_password(password):
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Create user document
        user_data = {
            'email': email,
            'username': username,
            'password_hash': password_hash.decode('utf-8'),
            'created_at': firestore.SERVER_TIMESTAMP,
            'auth_provider': 'email'
        }
        
        # Save to Firestore
        try:
            user_id = register_user(transaction, user_data)
        except Exception as e:
            if "Email already taken" in str(e):
                return jsonify({'error': 'Email already registered'}), 409
            elif "Username already taken" in str(e):
                return jsonify({'error': 'Username already taken'}), 409
            else:
                return jsonify({'error': f'Internal server error: {e}'}), 500
        
        # Return success response (without password hash)
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': user_id,
                'email': email,
                'username': username,
                'auth_provider': 'email'
            }
        }), 201
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
    

def find_user_id_by_identifier(identifier: str) -> str | None:
    """
    Find user ID by email or username identifier.
    Returns user ID if found, None otherwise.
    """
    # 1) Try identifier as email
    email_candidate = identifier.lower()
    email_ref = db.collection('userEmails').document(email_candidate)
    email_doc = email_ref.get()
    user_id = None

    if email_doc.exists and 'userId' in (email_doc.to_dict() or {}):
        user_id = email_doc.to_dict()['userId']
    else:
        # 2) Try identifier as username
        username_candidate = identifier  # preserve case; registration allowed A-Za-z0-9_
        username_ref = db.collection('usernames').document(username_candidate)
        username_doc = username_ref.get()
        if username_doc.exists and 'userId' in (username_doc.to_dict() or {}):
            user_id = username_doc.to_dict()['userId']
    return user_id

@app.route('/login', methods=['POST'])
def login():
    """
    Login with identifier (email or username) and password.
    Request: { "identifier": "...", "password": "..." }
    Response on success: { "token": "...", "user": { id, email, username, auth_provider } }
    """
    try:
        if not JWT_SECRET:
            return jsonify({'error': 'Server misconfiguration: JWT secret not set'}), 500

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        identifier = str(data.get('identifier', '')).strip()
        password = data.get('password', '')

        if not identifier or not password:
            return jsonify({'error': 'Identifier and password are required'}), 400
        
        user_id = None

        user_id = find_user_id_by_identifier(identifier)

        if not user_id:
            # Do not reveal which part failed
            return jsonify({'error': 'Invalid credentials'}), 401

        # Fetch user doc
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({'error': 'Invalid credentials'}), 401

        user_data = user_doc.to_dict() or {}
        auth_provider = user_data.get('auth_provider', 'email')
        
        # Check if this is a Google-only account
        if auth_provider == 'google':
            return jsonify({'error': 'This account was created with Google. Please use Google login instead.'}), 400
        
        # For email accounts, check password hash
        stored_hash = user_data.get('password_hash', '')
        if not stored_hash:
            return jsonify({'error': 'Invalid credentials'}), 401

        # Verify password
        try:
            if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                return jsonify({'error': 'Invalid credentials'}), 401
        except Exception:
            # In case of malformed hash, avoid leaking details
            return jsonify({'error': 'Invalid credentials'}), 401

        # Issue JWT
        token = issue_jwt(user_doc.id, user_data.get('email'), user_data.get('username'))

        return jsonify({
            'token': token,
            'user': {
                'id': user_doc.id,
                'email': user_data.get('email'),
                'username': user_data.get('username'),
                'auth_provider': user_data.get('auth_provider', 'email')
            }
        }), 200

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/signup/google', methods=['POST'])
def signup_google():
    """
    Create a new account using Google ID token with preferred username.
    Body: { "id_token": "...", "username": "preferred_name" }
    - Verifies Google token and requires verified email.
    - Ensures username availability with existing validation.
    - Creates user doc (auth_provider: "google", providers.google details).
    - Creates lookup docs userEmails/{email} and usernames/{username}.
    - Returns your JWT and user.
    """
    try:
        if not JWT_SECRET:
            return jsonify({'error': 'Server misconfiguration: JWT secret not set'}), 500

        data = request.get_json() or {}
        id_token_str = data.get('id_token', '')
        preferred_username = str(data.get('username', '')).strip()

        if not id_token_str or not preferred_username:
            return jsonify({'error': 'id_token and username are required'}), 400

        # Validate username format
        if not validate_username(preferred_username):
            return jsonify({'error': 'Username must be 3-30 characters, alphanumeric and underscores only'}), 400

        # Verify Google token and extract claims
        try:
            claims = verify_google_id_token(id_token_str)
        except Exception as e:
            return jsonify({'error': f'Invalid Google token: {str(e)}'}), 401

        email = claims['email'].lower().strip()
        sub = claims.get('sub')

        # Create user document data
        user_data = {
            'email': email,
            'username': preferred_username,
            'auth_provider': 'google',
            'providers': {
                'google': {
                    'sub': sub,
                    'linked_at': firestore.SERVER_TIMESTAMP
                }
            }
            # Do not include password_hash for Google accounts
            # created_at will be added by the transactional function
        }

        # Register user with transactional safety
        try:
            user_id = register_google_user(transaction, user_data, email, preferred_username)
        except Exception as e:
            if "Email already registered" in str(e):
                return jsonify({'error': 'Email already registered. Please link Google to your existing account.'}), 409
            elif "Username already taken" in str(e):
                return jsonify({'error': 'Username already taken'}), 409
            else:
                return jsonify({'error': f'Internal server error: {e}'}), 500

        token = issue_jwt(user_id, email, preferred_username)
        return jsonify({
            'token': token,
            'user': {
                'id': user_id,
                'email': email,
                'username': preferred_username,
                'auth_provider': 'google'
            }
        }), 201

    except Exception as e:
        print(f"Google signup error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/login/google', methods=['POST'])
def login_google():
    """
    Login with Google ID token for accounts previously created or linked.
    Body: { "id_token": "..." }
    - Verifies Google token (audience, signature, email_verified).
    - Looks up user by email and ensures google provider is present (or allow login if account is google-native).
    - Returns your JWT and user.
    """
    try:
        if not JWT_SECRET:
            return jsonify({'error': 'Server misconfiguration: JWT secret not set'}), 500

        data = request.get_json() or {}
        id_token_str = data.get('id_token', '')
        if not id_token_str:
            return jsonify({'error': 'id_token is required'}), 400

        try:
            claims = verify_google_id_token(id_token_str)
        except Exception as e:
            return jsonify({'error': f'Invalid Google token: {str(e)}'}), 401

        email = claims['email'].lower().strip()

        # Resolve user by email
        email_ref = db.collection('userEmails').document(email)
        email_doc = email_ref.get()
        if not email_doc.exists:
            return jsonify({'error': 'Account not found. Please sign up with Google first.'}), 404

        user_id = (email_doc.to_dict() or {}).get('userId')
        if not user_id:
            return jsonify({'error': 'Invalid credentials'}), 401

        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({'error': 'Invalid credentials'}), 401

        user_data = user_doc.to_dict() or {}
        providers = user_data.get('providers', {})
        # Enforce explicit linking: only allow login if google provider is present or auth_provider is google
        if not (user_data.get('auth_provider') == 'google' or 'google' in providers):
            return jsonify({'error': 'Google not linked to this account. Please link your Google account first.'}), 409

        token = issue_jwt(user_doc.id, user_data.get('email'), user_data.get('username'))
        return jsonify({
            'token': token,
            'user': {
                'id': user_doc.id,
                'email': user_data.get('email'),
                'username': user_data.get('username'),
                'auth_provider': user_data.get('auth_provider', 'email')
            }
        }), 200

    except Exception as e:
        print(f"Google login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'auth-service'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
