import slack_notifications as slack
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from email_model import Email


class Notifier:

    @staticmethod
    def slack_notify(channel, text):
        block = slack.SimpleTextBlock(
            'Security Breach',
            fields=[
                slack.SimpleTextBlock.Field(
                    'Text field',
                ),
                slack.SimpleTextBlock.Field(
                    'Text field',
                    emoji=True,
                ),
            ],
        )

        slack.send_notify(channel, username='Bot', text=text, blocks=[block])

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
