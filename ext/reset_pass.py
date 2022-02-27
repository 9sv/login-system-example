import secrets
import smtplib

reset_codes = dict()

def send_reset_code(email: str, url: str):
    smtp_server = smtplib.SMTP_SSL("SMTP_SERVER", int("SMTP_PORT"))
    smtp_server.login("YOUR_USERNAME", "YOUR_PASSWORD")
    reset_token = secrets.token_hex(256)
    reset_codes[reset_token] = email
    content = 'From: ' + "YOUR_FROM_EMAIL" + '\nSubject: ' + 'Reset Password' + '\n' + str(url + '/' + reset_token)
    smtp_server.sendmail("YOUR_FROM_EMAIL", str(email), content)
