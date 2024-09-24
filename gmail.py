import base64
import os
import re
import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# If modifying these SCOPES, delete the file token.json.
SCOPES = ["https://mail.google.com/", "https://www.googleapis.com/auth/gmail.modify"]

class NoVerifyRequest(Request):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = requests.Session()
        self.session.verify = False  # Desabilita a verificação de SSL

    def prepare_request(self, *args, **kwargs):
        return self.session.request(*args, **kwargs)

def authenticate_gmail():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(NoVerifyRequest())  # Usar a classe com SSL desabilitado
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds

def delete_email(service, message_id):
    try:
        service.users().messages().delete(userId="me", id=message_id).execute()
        print(f"Deleted message ID: {message_id}")
    except Exception as e:
        print(f"Error deleting message ID {message_id}: {e}")

def delete_unwanted_emails(service):
    query = "before:2019-01-01"  # Ajuste essa consulta conforme necessário
    page_token = None
    messages = []  # Inicializa a lista para acumular mensagens

    while True:
        results = service.users().messages().list(userId="me", q=query, pageToken=page_token).execute()
        page_messages = results.get("messages", [])
        messages.extend(page_messages)
        page_token = results.get('nextPageToken')
        if not page_token:
            break

    if not messages:
        print("No messages found.")
    else:
        print(f"Total messages found: {len(messages)}")
        # print("Deleting unwanted emails...")

        # for message in messages:
        #     message_id = message["id"]
        #     delete_email(service, message_id)

def main():
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)
    delete_unwanted_emails(service)

if __name__ == "__main__":
    main()
