from __future__ import print_function

import os.path
import base64
from bs4 import BeautifulSoup

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def get_payload(service, email_id):
    email = service.users().messages().get(userId='me', id=email_id).execute()
    return email['payload']

def get_subject(service, email_id):
    payload = get_payload(service, email_id)
    headers = payload['headers']
    for d in headers:
        if d['name'] == 'Subject':
            subject = d['value']
    return subject

def get_message(service, email_id):
    try:
        payload = get_payload(service, email_id)
        parts = payload.get('parts')[0]
        data = parts['body'].get('data')
        data = data.replace("-","+").replace("_","/")
        decoded_data = base64.b64decode(data)
        soup = BeautifulSoup(decoded_data , "lxml")
        body = soup.body()
        return body
    except:
        return None

def main():
    creds = authenticate()
    try:
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me').execute()
        email_ids = [message.get('id') for message in results.get('messages', [])]
        for email_id in email_ids:
            subject = get_subject(service, email_id)
            message = get_message(service, email_id)
            print(f'Subject: {subject}')
            print(f'Message: {message}')
            print('\n')

    except HttpError as error:
        print(f'An error occurred: {error}')


if __name__ == '__main__':
    main()