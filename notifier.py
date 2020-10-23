import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from slack import WebClient
from slack.errors import SlackApiError

from email_model import Email


class Notifier:

    @staticmethod
    def slack_notify(channel, text):
        client = WebClient(token=os.environ['SLACK_API_TOKEN'])
        try:
            client.chat_postMessage(channel='#' + channel, blocks=text)
        except SlackApiError as e:
            print(f"Got an error: {e.response['error']}")

    @staticmethod
    def email_notify(email: Email):
        message = MIMEMultipart("alternative")
        message["Subject"] = email.subject
        message["From"] = email.send_from
        message["To"] = email.send_to
        html_text = MIMEText(email.content, 'html')
        message.attach(html_text)
        with smtplib.SMTP(email.host, email.port) as server:
            server.starttls()
            if email.username and email.password:
                server.login(email.username, email.password)
            server.sendmail(email.send_from, email.send_to, message.as_string())
        print("Email sent to {email}".format(email=email.send_to))
