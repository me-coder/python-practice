from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status, Cookie, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import JWTError, jwt
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone

import logging
import os
import requests  # For making HTTP requests to GitHub

# Basic logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

if not all([JWT_SECRET_KEY, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET]):
    logger.error(
        "Missing one or more critical environment variables: JWT_SECRET_KEY, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET"
    )
    raise EnvironmentError(
        "Critical environment variables are not set. Please check your .env file."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Our application's token validity

# GitHub OAuth URLs
# The scope 'user' is enough to get basic user profile information including 'login' (username)
GITHUB_AUTH_URL = (
    f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope=user"
)
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com"

# FastAPI app instance
app = FastAPI()


# --- Pydantic Models ---
class TokenData(BaseModel):
    username: str | None = None  # 'sub' (subject) will hold the username


# --- JWT Helper Functions ---
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        # Default expiration time if not provided
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    access_token_cookie: str | None = Cookie(None),
) -> TokenData | None:
    """
    Dependency to get the current user from the JWT cookie.
    Returns TokenData if the token is valid, None otherwise.
    Does not raise an exception for invalid/missing tokens, allowing for optional authentication.
    """
    if access_token_cookie is None:
        logger.debug("No access_token_cookie found.")
        return None
    try:
        payload = jwt.decode(
            access_token_cookie, JWT_SECRET_KEY, algorithms=[ALGORITHM]
        )
        username: str | None = payload.get(
            "sub"
        )  # "sub" is standard for subject (username)
        if username is None:
            logger.info("Username (sub) not found in JWT payload.")
            return None
        logger.debug(f"Token decoded successfully for user: {username}")
        return TokenData(username=username)
    except JWTError as e:
        logger.info(f"Could not validate credentials (JWTError): {e}")
        return None


async def get_required_current_user(
    current_user: TokenData | None = Depends(get_current_user),
) -> TokenData:
    """
    Dependency that requires a user to be authenticated.
    If the user is not authenticated (current_user is None or has no username),
    it raises an HTTPException to redirect to the login page.
    """
    if not current_user or not current_user.username:
        logger.info(
            "User not authenticated, redirecting to /login for required authentication."
        )
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,  # Use 307 for temporary redirect
            detail="Not authenticated",
            headers={"Location": "/login"},  # Redirect to our login initiation endpoint
        )
    return current_user


# --- API Endpoints ---


@app.get("/", response_class=HTMLResponse)
async def read_root(current_user: TokenData | None = Depends(get_current_user)):
    """
    Root endpoint. Displays login button or user info.
    Uses `get_current_user` for optional authentication.
    """
    if current_user and current_user.username:
        logger.info(f"User {current_user.username} is logged in. Showing welcome page.")
        # User is logged in
        return f"""
        <html>
            <head><title>FastAPI OAuth Home</title></head>
            <body>
                <h1>Hello, <b>{current_user.username}</b> from FastAPI!</h1>
                <p>You are logged in using your GitHub account.</p>
                <p><a href="/protected">Go to protected info</a></p>
                <p><a href="/logout">Logout</a></p>
            </body>
        </html>
        """
    else:
        logger.info("User not logged in. Showing login page.")
        # User is not logged in, show login button
        # (Using the same button style as the Flask example for consistency)
        return """
        <!DOCTYPE html>
        <html>
        <head>
        <title>OAuth Login with FastAPI</title>
        <style>
          .github-button-container {
            display: inline-block; border-radius: 50%; overflow: hidden; cursor: pointer;
            transition: transform 0.1s ease-in-out, box-shadow 0.1s ease-in-out;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.2);
          }
          .github-button-container:active { transform: scale(0.85); box-shadow: none; }
          .github-button { display: block; }
        </style>
        </head>
        <body>
        <h1>Login Page for OAuth (FastAPI)</h1>
        <p>You are not currently logged in.</p>
        <div>
            Login with GitHub
            <span style="font-size:20px">    :    </span>
            <a href="/login">
              <div class="github-button-container">
                <svg class="github-button" height="48" aria-hidden="true" viewBox="0 0 24 24" version="1.1" width="48" data-view-component="true">
                    <path d="M12.5.75C6.146.75 1 5.896 1 12.25c0 5.089 3.292 9.387 7.863 10.91.575.101.79-.244.79-.546 0-.273-.014-1.178-.014-2.142-2.889.532-3.636-.704-3.866-1.35-.13-.331-.69-1.352-1.18-1.625-.402-.216-.977-.748-.014-.762.906-.014 1.553.834 1.769 1.179 1.035 1.74 2.688 1.25 3.349.948.1-.747.402-1.25.733-1.538-2.559-.287-5.232-1.279-5.232-5.678 0-1.25.445-2.285 1.178-3.09-.115-.288-.517-1.467.115-3.048 0 0 .963-.302 3.163 1.179.92-.259 1.897-.388 2.875-.388.977 0 1.955.13 2.875.388 2.2-1.495 3.162-1.179 3.162-1.179.633 1.581.23 2.76.115 3.048.733.805 1.179 1.825 1.179 3.09 0 4.413-2.688 5.39-5.247 5.678.417.36.776 1.05.776 2.128 0 1.538-.014 2.774-.014 3.162 0 .302.216.662.79.547C20.709 21.637 24 17.324 24 12.25 24 5.896 18.854.75 12.5.75Z"></path>
                </svg>
              </div>
            </a>
        </div>
        </body>
        </html>
        """


@app.get("/login")
async def login_with_github():
    """
    Redirects the user to GitHub's authorization page.
    """
    logger.info("Redirecting to GitHub for authentication.")
    return RedirectResponse(url=GITHUB_AUTH_URL, status_code=status.HTTP_302_FOUND)


@app.get("/auth/callback")
async def auth_callback(
    code: str, request: Request
):  # FastAPI automatically gets 'code' from query params
    """
    Handles the callback from GitHub after user authentication.
    Exchanges the code for a GitHub access token, fetches user info,
    creates an application JWT, and sets it as a cookie.
    """
    logger.info(
        f"Received callback from GitHub with code (first 20 chars): {code[:20]}..."
    )
    if not code:
        logger.error("No authorization code received from GitHub.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No authorization code received from GitHub.",
        )

    try:
        # 1. Exchange code for GitHub access token
        token_payload = {
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
        }
        headers = {"Accept": "application/json"}  # Important to get JSON response

        logger.info("Requesting access token from GitHub...")
        token_res = requests.post(GITHUB_TOKEN_URL, data=token_payload, headers=headers)
        token_res.raise_for_status()  # Raises HTTPError for bad responses (4XX or 5XX)
        token_json = token_res.json()

        github_access_token = token_json.get("access_token")
        if not github_access_token:
            logger.error(f"GitHub access token not found in response: {token_json}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch GitHub access token.",
            )
        logger.info("Successfully obtained GitHub access token.")

        # 2. Fetch user info from GitHub API using the token
        user_headers = {"Authorization": f"token {github_access_token}"}
        logger.info("Fetching user information from GitHub API...")
        user_res = requests.get(f"{GITHUB_API_URL}/user", headers=user_headers)
        user_res.raise_for_status()
        user_data = user_res.json()

        user_login = user_data.get("login")  # 'login' is the GitHub username
        if not user_login:
            logger.error(f"Could not get user login from GitHub user data: {user_data}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not fetch user login from GitHub.",
            )
        logger.info(f"Successfully fetched GitHub user login: {user_login}")

        # 3. Create JWT for our application
        # The 'sub' (subject) claim is standard for storing the user identifier
        app_jwt_token = create_access_token(data={"sub": user_login})

        # 4. Set the JWT as an HttpOnly cookie and redirect
        # Redirect to /protected or / after successful login
        response = RedirectResponse(
            url="/protected", status_code=status.HTTP_307_TEMPORARY_REDIRECT
        )
        response.set_cookie(
            key="access_token_cookie",
            value=app_jwt_token,
            httponly=True,  # Makes the cookie inaccessible to client-side JavaScript
            samesite="lax",  # "lax" or "strict". Lax is a good default.
            path="/",  # Cookie available for all paths
            # secure=True,      # Uncomment in production if served over HTTPS
            # max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60 # Optional: browser cookie expiry
        )
        logger.info(f"JWT cookie set for user {user_login}. Redirecting to /protected.")
        return response

    except requests.exceptions.RequestException as e:
        logger.error(f"RequestException during GitHub OAuth flow: {e}")
        # Provide a user-friendly error or redirect to an error page
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error communicating with GitHub: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Unexpected error during GitHub OAuth flow: {e}", exc_info=True)
        # Provide a user-friendly error or redirect to an error page
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {str(e)}",
        )


@app.get("/protected", response_class=HTMLResponse)
async def protected_route(current_user: TokenData = Depends(get_required_current_user)):
    """
    A protected route that requires authentication.
    Uses `get_required_current_user` which handles redirection if not authenticated.
    """
    logger.info(f"User {current_user.username} accessed protected route.")
    return f"""
    <html>
        <head><title>Protected Area</title></head>
        <body>
            <h1>Welcome to the Protected Area, <b style='color:royalblue;'>{current_user.username}</b>!</h1>
            <p>This content is only visible to authenticated users.</p>
            <p>(This is a protected resource in FastAPI.)</p>
            <p><a href="/">Go back to Home</a></p>
            <p><a href="/logout">Logout</a></p>
        </body>
    </html>
    """


@app.get("/logout")
async def logout():
    """
    Logs the user out by deleting the access token cookie and redirecting to home.
    """
    logger.info("User logging out.")
    response = RedirectResponse(url="/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response.delete_cookie(
        key="access_token_cookie", path="/"
    )  # Ensure path matches where it was set
    logger.info("Access token cookie deleted. Redirecting to home.")
    return response


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Uvicorn server on http://127.0.0.1:8000")
    # host="0.0.0.0" makes it accessible from your network, not just localhost
    uvicorn.run(app, host="0.0.0.0", port=8000)
