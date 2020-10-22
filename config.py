import os

EMAIL_CONFIG = {"host": os.getenv("LEAK_ALERTER_EMAIL_HOST"),
                "port": os.getenv("LEAK_ALERTER_EMAIL_PORT", 587),
                "username": os.getenv("LEAK_ALERTER_EMAIL_USERNAME", None),
                "password": os.getenv("LEAK_ALERTER_EMAIL_PASSWORD", None),
                "send_to": os.getenv("LEAK_ALERTER_EMAIL_SEND_TO"),
                "send_from": os.getenv("LEAK_ALERTER_EMAIL_SEND_FROM"),
                "subject": os.getenv("LEAK_ALERTER_EMAIL_SUBJECT", "Email found in security breach")
                }
