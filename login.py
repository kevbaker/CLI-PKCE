import base64
import hashlib
import json
import os
import pathlib
import requests
import secrets
import threading
import urllib
import webbrowser
from time import sleep

from werkzeug.serving import make_server

import dotenv
from flask import Flask, request


# Load Settings from dotenv
env_path = pathlib.Path('.') / '.env'
dotenv.load_dotenv(dotenv_path=env_path)

# Set Identity Provider Settings
auth_listener_host = os.getenv('AUTH_LISTENER_HOST')
auth_listener_port = os.getenv('AUTH_LISTENER_PORT')
auth_client_id = os.getenv('AUTH_CLIENT_ID')
auth_tenant = os.getenv('AUTH_TENANT')
# auth_clients_url = os.getenv('AUTH_CLIENTS_URL')
auth_authorize_url = os.getenv('AUTH_AUTHORIZE_URL')
auth_token_url = os.getenv('AUTH_TOKEN_URL')
auth_audience_url = os.getenv('AUTH_AUDIENCE_URL')
auth_scopes = os.getenv('AUTH_SCOPES')

# Setup Auth Listener
app = Flask(__name__)
@app.route("/callback")
def callback():
    """
    The callback is invoked after a completed login attempt (succesful or otherwise).
    It sets global variables with the auth code or error messages, then sets the
    polling flag received_callback.
    :return:
    """
    global received_callback, code, error_message, received_state
    error_message = None
    code = None
    if 'error' in request.args:
        error_message = request.args['error'] + ': ' + request.args['error_description']
    else:
        code = request.args['code']
    received_state = request.args['state']
    received_callback = True
    return "Please return to your application now."


class ServerThread(threading.Thread):
    """
    The Flask server is done this way to allow shutting down after a single request has been received.
    """

    def __init__(self, app):
        threading.Thread.__init__(self)
        self.srv = make_server(auth_listener_host, auth_listener_port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        print('starting server')
        self.srv.serve_forever()

    def shutdown(self):
        self.srv.shutdown()


def auth_url_encode(byte_data):
    """
    Safe encoding handles + and /, and also replace = with nothing
    :param byte_data:
    :return:
    """
    return base64.urlsafe_b64encode(byte_data).decode('utf-8').replace('=', '')


def generate_challenge(a_verifier):
    return auth_url_encode(hashlib.sha256(a_verifier.encode()).digest())


# Setup auth variables
verifier = auth_url_encode(secrets.token_bytes(32))
challenge = generate_challenge(verifier)
state = auth_url_encode(secrets.token_bytes(32))
redirect_uri = f"http://{auth_listener_host}:{auth_listener_port}/callback"



# We generate a nonce (state) that is used to protect against attackers invoking the callback
# base_url = 'https://%s.auth0.com/authorize?' % tenant
base_url = f"{auth_authorize_url}?"
url_parameters = {
    # 'audience': auth_audience_url,
    'scope': auth_scopes,
    'response_type': 'code',
    'redirect_uri': redirect_uri,
    'client_id': auth_client_id,
    'code_challenge': challenge.replace('=', ''),
    'code_challenge_method': 'S256',
    'state': state
}
url = base_url + urllib.parse.urlencode(url_parameters)

# Open the browser window to the login url
# Start the server
# Poll til the callback has been invoked
received_callback = False
webbrowser.open_new(url)
server = ServerThread(app)
server.start()
while not received_callback:
    sleep(1)
server.shutdown()

if state != received_state:
    print("Error: session replay or similar attack in progress. Please log out of all connections.")
    exit(-1)

if error_message:
    print("An error occurred:")
    print(error_message)
    exit(-1)

# Exchange the code for a token
# url = 'https://%s.auth0.com/oauth/token' % tenant
url = auth_token_url
headers = {'Content-Type': 'application/json'}
body = {'grant_type': 'authorization_code',
        'client_id': client_id,
        'code_verifier': verifier,
        'code': code,
        'audience': 'https://gateley-empire-life.auth0.com/api/v2/',
        'redirect_uri': redirect_uri}
r = requests.post(url, headers=headers, data=json.dumps(body))
data = r.json()
print("REQUEST RESULTS:")
print(json.dumps(data))


# Use the token to list the clients
# url = 'https://%s.auth0.com/api/v2/clients' % tenant
# url = auth_clients_url
# headers = {'Authorization': 'Bearer %s' % data['access_token']}
# r = requests.get(url, headers=headers)
# data = r.json()

# for client in data:
#     print("Client: " + client['name'])
