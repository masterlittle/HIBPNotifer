from dataclasses import dataclass


@dataclass
class Email:
    send_to: list
    send_from: str
    subject: str
    content: str
    host: str
    port: int = 587
    username: str = None
    password: str = None
    attachment_files: str = None

    @property
    def smtp(self):
        if not self.username and not self.password:
            return {'host': self.host, 'timeout': 5, 'port': self.port}
        else:
            return {'host': self.host, 'timeout': 5, 'port': self.port,
                    'user': self.username, 'password': self.password}
