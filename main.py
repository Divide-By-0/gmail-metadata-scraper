import os
import base64
import json
import re
from flask import Flask, request, redirect, session, render_template
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from pickle import dumps, loads
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Read from .env

# OAuth2 client info
CLIENT_ID = os.getenv('CLIENT_ID')  # Read from .env
CLIENT_SECRET = os.getenv('CLIENT_SECRET')  # Read from .env
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Set up Gmail API credentials
# credentials = Credentials.from_authorized_user_file('credentials.json', ['https://www.googleapis.com/auth/gmail.readonly'])

# Function to retrieve the longest from email address
def get_longest_from_address(emails):
    longest_address = ''
    longest_length = 0
    for email in emails:
        from_address = email['payload']['headers'][0]['value']
        if len(from_address) > longest_length:
            longest_address = from_address
            longest_length = len(from_address)
    return longest_address

# Function to retrieve the longest to email address
def get_longest_to_address(emails):
    longest_address = ''
    longest_length = 0
    for email in emails:
        to_addresses = [header['value'] for header in email['payload']['headers'] if header['name'] == 'To']
        for to_address in to_addresses:
            if len(to_address) > longest_length:
                longest_address = to_address
                longest_length = len(to_address)
    return longest_address

# Function to retrieve the longest message ID
def get_longest_message_id(emails):
    longest_message_id = ''
    longest_length = 0
    for email in emails:
        message_id = email['payload']['headers'][9]['value']
        if len(message_id) > longest_length:
            longest_message_id = message_id
            longest_length = len(message_id)
    return longest_message_id

# Function to retrieve the last N emails
def retrieve_emails(limit):
    credentials_dict = session['credentials']
    credentials = Credentials.from_authorized_user_info(credentials_dict)
    service = build('gmail', 'v1', credentials=credentials)
    results = service.users().messages().list(userId='me', maxResults=limit).execute()
    emails = []
    if 'messages' in results:
        emails.extend(results['messages'])
    while 'nextPageToken' in results:
        page_token = results['nextPageToken']
        results = service.users().messages().list(userId='me', maxResults=limit, pageToken=page_token).execute()
        if 'messages' in results:
            emails.extend(results['messages'])
    return emails

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}
    

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uris": ["http://localhost:5000/oauth2callback", "http://127.0.0.1:5000/oauth2callback"],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth", "redirect_uri": "http://127.0.0.1:5000/oauth2callback",
                "redirect_uri": "http://127.0.0.1:5000/oauth2callback", 
                "token_uri": "https://accounts.google.com/o/oauth2/token",
            }
        },
        scopes=SCOPES,
        state=session.new
    )
    flow.redirect_uri = "http://127.0.0.1:5000/oauth2callback";
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    session['state'] = state

    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']

    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uris": ["http://localhost:5000/oauth2callback", "http://127.0.0.1:5000/oauth2callback"],
                "redirect_uri": "http://127.0.0.1:5000/oauth2callback",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
            }
        },
        scopes=SCOPES,
        state=state
    )

    flow.redirect_uri = "http://127.0.0.1:5000/oauth2callback";
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    service = build('gmail', 'v1', credentials=credentials)    
    return render_template('index.html')

# Route for the home page
@app.route('/')
def home():
    return render_template('index.html')

# Route for retrieving and displaying the results
@app.route('/results')
def results():
    limit = 1000  # Number of emails to retrieve
    emails = retrieve_emails(limit)

    longest_from_address = get_longest_from_address(emails)
    longest_to_address = get_longest_to_address(emails)
    longest_message_id = get_longest_message_id(emails)

    return render_template('results.html', 
                           longest_from_address=longest_from_address, 
                           longest_to_address=longest_to_address, 
                           longest_message_id=longest_message_id)

if __name__ == '__main__':
    app.run('127.0.0.1', debug=True)
    
