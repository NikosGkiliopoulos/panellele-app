import ssl
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import certifi

sender_email = "mpazmpaz21@gmail.com"
app_password = "yvusbrrebigyupco"  # όχι το κανονικό σου password!
receiver_email = "nikosss2005@gmail.com"

message = MIMEMultipart("alternative")
message["Subject"] = "Test Email"
message["From"] = sender_email
message["To"] = receiver_email

text = "Γεια σου μικρο μου πονυ."
part = MIMEText(text, "plain")
message.attach(part)

# Δημιουργία προσαρμοσμένου context SSL με το πιστοποιητικό
context = ssl.create_default_context(cafile=certifi.where())

with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
    server.login(sender_email, app_password)
    server.sendmail(sender_email, receiver_email, message.as_string())