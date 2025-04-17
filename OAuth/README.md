# How To Setup OAuth (using GitHub)
1. Login to [GitHub](https://github.com/)
1. Open [GitHub Settings -> Developer Settings -> OAuth Apps](https://github.com/settings/developers/)
1. Click **New OAuth App** button to create OAuth token
1. If you are experimenting add following details:
    > Application name = OAuth Example
    > Homepage URL = http://127.0.0.1:5000
    > Application description = To understand working of OAuth with Python libraries
    > Authorization callback URL = http://127.0.0.1:5000/auth/callback
    > Enable Device Flow = _Leave unchecked_
    and click **_Register application_** button.
1. The page presented displays a **Client ID**.
    On the same page against **Client secrets** click _Generate a new client secret_
    Enter password and continue to land back on same page, now with **Client ID** and **Client secrets**
1. Copy **Client ID** and **Client secrets** to .env file as under:
    ```ini
    JWT_SECRET_KEY=""
    GITHUB_CLIENT_ID="<GITHUB_CLIENT_ID>"
    GITHUB_CLIENT_SECRET="<GITHUB_CLIENT_SECRET>"
    ```
    **_NOTE_**: Failing to save GITHUB_CLIENT_SECRET would require creating a new secret as the value is displayed only once.
1. Upon populating the .env file, click **Update application**
1. To generate JWT_SECRET_KEY in .env, open **Bash** prompt and type:
    ```shell
    $ python -c "import secrets; print(secrets.token_urlsafe(32))"
    ```
    Fill in this value in the .env file to complete the file.
    ```ini
    JWT_SECRET_KEY="<JWT_SECRET_KEY>"
    GITHUB_CLIENT_ID="<GITHUB_CLIENT_ID>"
    GITHUB_CLIENT_SECRET="<GITHUB_CLIENT_SECRET>"
    ```
With these steps the stage is set to tryout our python examples:
1. oauth_flask.py:      OAuth login example using flask microframework
1. oauth_fastapi.py:    OAuth login example using fastapi web framework

# Envioronment Preparation
Install the prerequisites
```shell
$ python -m pip install --upgrade pip --requirement ./requirements.txt
```

## OAuth Using Flask
Run command to launch the flask application:
```shell
$ python ./oauth_flask.py
```

Once the application is launched, open the following URL in a browser:
http://127.0.0.1:5000

**NOTE**: `localhost` might not work as it can resolve to IPV6 address which is _::1_,
and the colons would interfere with port 5000 demarcation in url.

If the application fails to open in browser, check firewall settings.
Disable firewall, if necessary.

## OAuth Using FastAPI
```shell
$ python ./oauth_fastapi.py
```

Once the application is launched, open the following URL in a browser:
http://127.0.0.1:8000
