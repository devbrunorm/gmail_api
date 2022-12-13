from __future__ import print_function

import os.path
import base64
from bs4 import BeautifulSoup

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from apiclient import errors

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

def download_attachments(service, email_id, destination_folder = "./attachments"):
    try:
        payload = get_payload(service, email_id)
        for part in payload.get('parts'):
            if part['filename']:
                if 'data' not in part['body']:
                    attachment_id = part['body']['attachmentId']
                    attachment = service.users().messages().attachments().get(userId='me', messageId=email_id,id=attachment_id).execute()
                    data = attachment['data']
        file_data = base64.urlsafe_b64decode(data.encode('UTF-8'))
        path = f"./attachments/{part['filename']}"

        with open(path, 'wb') as f:
            f.write(file_data)

    except errors.HttpError as error:
        print(f'An error occurred: {error}')

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
        results = service.users().messages().list(userId='me', 
            q=f'from:no-reply@ccee.org.br after:2022/12/13').execute()
        email_ids = [message.get('id') for message in results.get('messages', [])]
        for email_id in email_ids:
            subject = get_subject(service, email_id)
            message = get_message(service, email_id)
            print(f'Subject: {subject}')
            print(f'Message: {message}')
            print('\n')

            download_attachments(service, email_id)

    except HttpError as error:
        print(f'An error occurred: {error}')


if __name__ == '__main__':
    main()