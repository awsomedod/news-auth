from flask import Flask
from firebase_admin import credentials, firestore, initialize_app
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
GOOGLE_CLIENT_ID = get_secret("GOOGLE_CLIENT_ID")

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