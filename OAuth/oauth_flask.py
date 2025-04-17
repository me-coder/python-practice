from dotenv import load_dotenv
from flask import (
    Flask,
    make_response,
    redirect,
    request,
    url_for,
)
from flask.wrappers import Response
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required,
    JWTManager,
)

import logging
import os
import requests

if not os.environ.get("GITHUB_CLIENT_ID"):
    from dotenv import load_dotenv

    load_dotenv()

logging.basicConfig(
    level=logging.DEBUG if os.environ.get("FLASK_DEBUG") else logging.ERROR
)
logger = logging.getLogger(__name__)

jwt = JWTManager(app=app)

# GitHub App credentials
# Check if the variables exist before accesing them
load_dotenv()
if not (
    os.environ.get("GITHUB_CLIENT_ID")
    and os.environ.get("GITHUB_CLIENT_SECRET")
    and os.environ.get("JWT_SECRET_KEY")
):
    raise Exception(
        "You need to define GITHUB_CLIENT_ID"
        ", GITHUB_CLIENT_SECRET & JWT_SECRET_KEY "
        "as enviroment variables."
    )

app = Flask(import_name=__name__)
# To generate a secret execute the following command:
# `python -c 'import secrets; print(secrets.token_urlsafe(32))'`
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
jwt = JWTManager(app=app)

GITHUB_URL = f"https://github.com/login/oauth/authorize?client_id={os.environ.get('GITHUB_CLIENT_ID')}&scope=user"
GITHUB_API_URL = "https://api.github.com"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"


@app.route(rule="/")
@jwt_required(optional=True, locations=["cookies"])
def index() -> str:
    """
    Handles the root route of the application.

    This route serves as the entry point for users.
    If a user is already authenticated (i.e., a valid JWT is present),
    a personalized greeting is displayed.
    Otherwise, a link to log in with GitHub is shown.

    Returns:
        str: A personalized greeting if the user is authenticated, or a
             login link if not.
    """
    current_user = get_jwt_identity()
    if current_user:
        return f"""
        Hello, <b>{current_user}</b> from index </br>
        <a href='protected'>Go to protected info</a>
        """
    else:
        return """
        <!DOCTYPE html>
        <html>
        <head>
        <title>OAuth Login</title>
        <style>
          .github-button-container {
            display: inline-block; /* Make the container fit the content */
            border-radius: 50%; /* Make the container round */
            overflow: hidden; /* Hide the overflow of the SVG */
            cursor: pointer;
            transition: transform 0.1s ease-in-out, box-shadow 0.1s ease-in-out;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.2); /* Add shadow */
          }

          .github-button-container:active {
            transform: scale(0.85);
            box-shadow: none; /* Remove shadow on click */
          }

          .github-button {
            display: block; /* Make the SVG fill the container */
          }
        </style>
        </head>
        <body>
        <h1>Login Page for OAuth</h1>
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
def login() -> Response:
    """
    Redirects the user to GitHub's authorization page.

    This route initiates the OAuth 2.0 flow by redirecting the user to
    GitHub, where they can authorize the application to access their
    GitHub account.

    Returns:
        Response: A redirect response to the GitHub authorization URL.
    """
    return make_response(redirect(location=GITHUB_URL))


@app.route(rule="/auth/callback")
def callback() -> Response:
    """
    Handles the callback from GitHub after user authentication.

    This route is the redirect URI that GitHub sends the user to after
    they have authorized the application. It exchanges the authorization
    code for an access token, retrieves user data from GitHub's API,
    creates a JWT, and sets it as a cookie in the response.

    Returns:
        Response: A redirect response to the protected route with the JWT
                  set as a cookie, or an error response if something fails.
    """
    code = request.args.get(key="code")
    if not code:
        return make_response({"error": "No code received from GitHub."}, 400)

    client_id = os.environ.get("GITHUB_CLIENT_ID")
    client_secret = os.environ.get("GITHUB_CLIENT_SECRET")

    try:
        data = {"client_id": client_id, "client_secret": client_secret, "code": code}
        headers = {"Accept": "application/json"}
        response = requests.post(url=GITHUB_TOKEN_URL, data=data, headers=headers)
        response.raise_for_status()

        try:
            access_token = response.json().get("access_token")
            if not access_token:
                logger.critical("Access token not found in response text either.")
                return make_response(
                    {"error": "Access token not found in response text either."}
                )
        except Exception as e:
            logger.critical(
                f"Critical error when extracting the token from the text: {e}"
            )
            return make_response(
                {
                    "error": f"Critical error when extracting the token from the text: {e}"
                }
            )

        if not "bearer" in response.json()["token_type"]:
            logger.critical(
                f"Received access token type is: {response.json()["token_type"]}. "
                "Only bearer is supported typetoken_type."
            )

        headers = {"Authorization": f"token {access_token}"}
        user_response = requests.get(url=f"{GITHUB_API_URL}/user", headers=headers)
        user_response.raise_for_status()
        user_data = user_response.json()

        jwt_access_token = create_access_token(identity=user_data.get("login"))
        # return jsonify(jwt_access_token=jwt_access_token)
        response = make_response(redirect(location=url_for(endpoint="protected")))
        response.set_cookie(
            key="access_token_cookie",
            value=jwt_access_token,
            httponly=True,
            secure=not app.debug,
            samesite="Lax",
            path='/'
        )
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: An error occurred during the request: {e}")
        return make_response(
            {"error": f"An error occurred during the request: {e}"}, 500
        )
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return make_response({"error": f"An error occurred: {e}"}, 500)


@app.route(rule="/protected")
@jwt_required(locations=["cookies"])
def protected() -> str:
    """
    A protected route that requires a valid JWT in a cookie.

    This route is only accessible to authenticated users. It retrieves
    the user's identity from the JWT and displays a personalized
    greeting.

    Returns:
        str: A personalized greeting for the authenticated user.
    """
    return "Hello, <b style='color:royalblue;'>{}</b>!</br>(This is a protected resource.)".format(
        get_jwt_identity()
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
