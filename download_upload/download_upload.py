# --- Standard Imports ---
import os
import logging

# --- Third-party Imports ---
from dotenv import load_dotenv
from flask import (
    Flask,
    request,
    send_from_directory,
    jsonify,
    url_for,
    redirect,
    make_response,
)
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required,
    JWTManager,
)
# Remove unused Response import:
# from flask.wrappers import Response # Import Response for type hinting if needed
from flask_wtf.csrf import CSRFProtect, generate_csrf # Import CSRFProtect and generate_csrf

import requests

# --- Logging Setup ---
logging.basicConfig(
    level=logging.DEBUG if os.environ.get("FLASK_DEBUG") else logging.ERROR
)
logger = logging.getLogger(__name__)

# --- Configuration and Environment Variables ---
load_dotenv()

# Check if required environment variables are set
# Added FLASK_SECRET_KEY requirement
if not (
    os.environ.get("GITHUB_CLIENT_ID")
    and os.environ.get("GITHUB_CLIENT_SECRET")
    and os.environ.get("JWT_SECRET_KEY")
    and os.environ.get("FLASK_SECRET_KEY") # Added check for Flask's secret key
):
    raise Exception(
        "You need to define GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, "
        "JWT_SECRET_KEY, and FLASK_SECRET_KEY as environment variables in a .env file." # Updated message
    )

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Flask Secret Key for Sessions and CSRF ---
# Generate a secret key using: python -c 'import secrets; print(secrets.token_hex(16))'
# Store it in your .env file as FLASK_SECRET_KEY
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY")

# --- CSRF Protection Initialization ---
# Initialize CSRF protection after setting the SECRET_KEY
csrf = CSRFProtect(app)

# --- File Upload Configuration ---
UPLOAD_FOLDER = '/mnt/s3fs-bucket'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- JWT Configuration ---
# Generate a secret key using: python -c 'import secrets; print(secrets.token_urlsafe(32))'
# Store it in your .env file as JWT_SECRET_KEY
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
jwt = JWTManager(app=app)

# --- GitHub OAuth Configuration ---
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
GITHUB_URL = f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope=user"
GITHUB_API_URL = "https://api.github.com"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"


# --- Routes ---

@app.route(rule="/")
@jwt_required(optional=True, locations=["cookies"]) # Allow access even without JWT, but check identity
def index() -> str:
    """
    Serves the main index page.
    Shows login button if not authenticated, or links to upload/download if authenticated.
    """
    current_user = get_jwt_identity()
    print(f"Current user: {current_user}")  # Debugging line to check current user
    if current_user:
        # User is logged in
        return f'''
        <!doctype html>
        <title>File Service - Welcome</title>
        <h1>Welcome, <b style='color:royalblue;'>{current_user}</b>!</h1>
        <p>You are logged in via GitHub.</p>
        <ul>
            <li><a href="/upload_page">Upload a File</a></li>
            <li><a href="/files">Download Files</a></li>
        </ul>
        <p><a href="/logout">Logout</a></p>
        '''
    else:
        # User is not logged in
        return """
        <!DOCTYPE html>
        <html>
        <head>
        <title>Login Required</title>
        <style>
          body { font-family: sans-serif; }
          .github-button-container {
            display: inline-block; border-radius: 50%; overflow: hidden;
            cursor: pointer; transition: transform 0.1s ease-in-out, box-shadow 0.1s ease-in-out;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.2); vertical-align: middle;
          }
          .github-button-container:active { transform: scale(0.85); box-shadow: none; }
          .github-button { display: block; }
        </style>
        </head>
        <body>
        <h1>Welcome to the File Service</h1>
        <p>Please log in with GitHub to manage files.</p>
        <div>
            Login with GitHub
            <span style="font-size:20px">    :    </span>
            <a href="/login">
              <div class="github-button-container">
                <svg class="github-button" height="48" aria-hidden="true" viewBox="0 0 24 24" version="1.1" width="48" data-view-component="true" class="octicon octicon-mark-github v-align-middle">
                    <path d="M12.5.75C6.146.75 1 5.896 1 12.25c0 5.089 3.292 9.387 7.863 10.91.575.101.79-.244.79-.546 0-.273-.014-1.178-.014-2.142-2.889.532-3.636-.704-3.866-1.35-.13-.331-.69-1.352-1.18-1.625-.402-.216-.977-.748-.014-.762.906-.014 1.553.834 1.769 1.179 1.035 1.74 2.688 1.25 3.349.948.1-.747.402-1.25.733-1.538-2.559-.287-5.232-1.279-5.232-5.678 0-1.25.445-2.285 1.178-3.09-.115-.288-.517-1.467.115-3.048 0 0 .963-.302 3.163 1.179.92-.259 1.897-.388 2.875-.388.977 0 1.955.13 2.875.388 2.2-1.495 3.162-1.179 3.162-1.179.633 1.581.23 2.76.115 3.048.733.805 1.179 1.825 1.179 3.09 0 4.413-2.688 5.39-5.247 5.678.417.36.776 1.05.776 2.128 0 1.538-.014 2.774-.014 3.162 0 .302.216.662.79.547C20.709 21.637 24 17.324 24 12.25 24 5.896 18.854.75 12.5.75Z"></path>
                </svg>
              </div>
            </a>
        </div>
        </body>
        </html>
        """

@app.route(rule="/login")
def login(): # Removed type hint -> Response as make_response returns Response anyway
    """Redirects the user to GitHub's authorization page."""
    logger.info("Redirecting user to GitHub for authentication.")
    return make_response(redirect(location=GITHUB_URL))

@app.route(rule="/logout")
def logout(): # Removed type hint -> Response
    """Logs the user out by clearing the JWT cookie."""
    logger.info("Logging out user.")
    response = make_response(redirect(url_for('index')))
    response.delete_cookie('access_token_cookie', path='/', samesite='Lax') # Ensure path and samesite match set_cookie
    return response


@app.route(rule="/auth/callback")
def callback(): # Removed type hint -> Response
    """
    Handles the callback from GitHub after user authentication.
    Exchanges code for token, gets user info, creates JWT, sets cookie, redirects to index.
    """
    code = request.args.get(key="code")
    if not code:
        logger.error("No authorization code received from GitHub.")
        return make_response(jsonify({"error": "No code received from GitHub."}), 400)

    logger.debug("Received authorization code from GitHub. Exchanging for access token.")
    try:
        # --- Exchange code for access token ---
        data = {"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": code}
        headers = {"Accept": "application/json"}
        token_response = requests.post(url=GITHUB_TOKEN_URL, data=data, headers=headers)
        token_response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        token_data = token_response.json()

        access_token = token_data.get("access_token")
        token_type = token_data.get("token_type", "").lower()

        if not access_token:
            logger.critical("Access token not found in GitHub response: %s", token_data)
            return make_response(jsonify({"error": "Access token not found in GitHub response."}), 500)

        if "bearer" not in token_type:
            logger.warning("Received non-bearer token type: %s", token_type)
            # Depending on strictness, you might want to reject non-bearer tokens
            # return make_response(jsonify({"error": f"Unsupported token type: {token_type}"}), 500)

        logger.debug("Access token received. Fetching user info from GitHub API.")

        # --- Get user info from GitHub API ---
        user_headers = {"Authorization": f"token {access_token}"} # Use "token" prefix for GitHub API
        user_response = requests.get(url=f"{GITHUB_API_URL}/user", headers=user_headers)
        user_response.raise_for_status() # Check for errors fetching user info
        user_data = user_response.json()
        github_login = user_data.get("login")

        if not github_login:
            logger.error("Could not get user login from GitHub API response: %s", user_data)
            return make_response(jsonify({"error": "Failed to get user information from GitHub."}), 500)

        logger.info("Successfully authenticated user: %s", github_login)

        # --- Create JWT and set cookie ---
        jwt_access_token = create_access_token(identity=github_login)
        response = make_response(redirect(location=url_for(endpoint="index"))) # Redirect to index after login
        response.set_cookie(
            key="access_token_cookie",
            value=jwt_access_token,
            httponly=True, # Prevent client-side JS access
            secure=not app.debug, # Use secure=True in production (HTTPS)
            samesite="Lax", # Good default for security
            path='/'
        )
        print(f"{response=}")  # Debugging line to see the response object
        logger.debug("JWT cookie set for user %s. Redirecting to index.", github_login)
        return response

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during GitHub OAuth callback: {e}", exc_info=True)
        return make_response(jsonify({"error": f"Network error during authentication: {e}"}), 502) # Bad Gateway
    except Exception as e:
        logger.error(f"Unexpected error during GitHub OAuth callback: {e}", exc_info=True)
        return make_response(jsonify({"error": f"An unexpected error occurred during authentication: {e}"}), 500)


# --- Protected File Management Routes ---

@app.route('/upload_page', methods=['GET'])
@jwt_required(locations=["cookies"]) # Require JWT cookie
def upload_page():
    """Serves the page with the upload form. Requires login."""
    current_user = get_jwt_identity()
    # Use generate_csrf() to get the token value for the form
    return f'''
    <!doctype html>
    <title>Upload New File</title>
    <h1>Upload New File</h1>
    <p>Logged in as: {current_user}</p>
    <form action="/upload" method="post" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" value="{generate_csrf()}"/>
      <input type="file" name="file">
      <input type="submit" value="Upload">
    </form>
    <p><a href="/">Back to Home</a></p>
    '''

@app.route('/upload', methods=['POST'])
@jwt_required(locations=["cookies"]) # Require JWT cookie
# CSRFProtect automatically protects POST requests, no decorator needed here
def upload_file():
    """Handles the file upload logic. Requires login."""
    current_user = get_jwt_identity() # Optional: Log who uploaded
    # Remove the incorrect csrf.generate_csrf() call here
    # csrf.generate_csrf() # <-- REMOVE THIS LINE

    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Sanitize filename (optional but recommended)
    # from werkzeug.utils import secure_filename
    # filename = secure_filename(file.filename)
    filename = file.filename # Use original for simplicity here

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        file.save(filepath)
        logger.info(f"User '{current_user}' uploaded file '{filename}'")
        return f'''
        <!doctype html>
        <title>Upload Success</title>
        <h1>Upload Successful</h1>
        <p>File '{filename}' uploaded successfully.</p>
        <p><a href="/upload_page">Upload Another File</a></p>
        <p><a href="/files">View Available Files</a></p>
        <p><a href="/">Back to Home</a></p>
        '''
    except Exception as e:
        logger.error(f"Error saving file '{filename}' for user '{current_user}': {e}", exc_info=True)
        return jsonify({"error": f"Could not save file: {e}"}), 500


@app.route('/download/<path:filename>', methods=['GET']) # Use path converter for filenames with slashes
@jwt_required(locations=["cookies"]) # Require JWT cookie
def download_file(filename):
    """Handles downloading a specific file. Requires login."""
    current_user = get_jwt_identity() # Optional: Log who downloaded
    logger.info(f"User '{current_user}' attempting to download file '{filename}'")
    try:
        # Security: Ensure the filename doesn't try to escape the UPLOAD_FOLDER
        # send_from_directory handles this reasonably well.
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True # Prompt download
        )
    except FileNotFoundError:
        logger.warning(f"User '{current_user}' requested non-existent file '{filename}'")
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        logger.error(f"Error sending file '{filename}' for user '{current_user}': {e}", exc_info=True)
        return jsonify({"error": "Could not send file"}), 500


@app.route('/files', methods=['GET'])
@jwt_required(locations=["cookies"]) # Require JWT cookie
def list_files():
    """Lists available files for download. Requires login."""
    current_user = get_jwt_identity()
    try:
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        # Optional: Filter out directories if any exist
        files = [f for f in files if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], f))]
    except OSError as e:
        logger.error(f"Error listing files in upload directory: {e}", exc_info=True)
        return jsonify({"error": "Could not list files"}), 500

    if not files:
        return f'''
        <!doctype html>
        <title>Download Files</title>
        <h1>No files available for download</h1>
        <p>Logged in as: {current_user}</p>
        <p><a href="/upload_page">Upload a File</a></p>
        <p><a href="/">Back to Home</a></p>
        '''

    file_links = [f'<li><a href="{url_for("download_file", filename=file)}">{file}</a></li>' for file in files]
    return f'''
    <!doctype html>
    <title>Download Files</title>
    <h1>Available Files</h1>
    <p>Logged in as: {current_user}</p>
    <ul>{"".join(file_links)}</ul>
    <p><a href="/upload_page">Upload a File</a></p>
    <p><a href="/">Back to Home</a></p>
    '''

# --- Main Execution ---
if __name__ == '__main__':
    # Use host='0.0.0.0' to make it accessible on your network
    # debug=True is useful for development, but should be False in production
    # Ensure debug is False if secure=True is used for cookies
    app.run(host='0.0.0.0', port=5000, debug=True) # Set debug=False for production
