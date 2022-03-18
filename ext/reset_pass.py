import secrets
import smtplib

reset_codes = dict()

def send_reset_code(email: str, config: list[str]):
    smtp_server = smtplib.SMTP_SSL(str(config["SMTP"]["SMTP_SERVER"]), int(config["SMTP"]["SMTP_PORT"]))
    smtp_server.login(str(config["SMTP"]["SMTP_USERNAME"]), str(config["SMTP"]["SMTP_PASSWORD"]))
    reset_token = secrets.token_hex(256)
    reset_codes[reset_token] = email
    content = 'From: ' + str(config["SMTP"]["FROM_EMAIL"]) + '\nSubject: ' + 'Reset Password' + '\n' + str(str(config["SERVER"]["DOMAIN"]) + '/' + reset_token)
    smtp_server.sendmail(str(config["SMTP"]["FROM_EMAIL"]), str(email), content)
