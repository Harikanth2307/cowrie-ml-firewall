import smtplib
from email.mime.text import MIMEText

def send_email_alert(ip_list):
    sender_email = ""  # use new email id or existing one
    receiver_email = ""  # receiver email id/ can put the same sender email
    app_password = ""  # Gmail app password (16-digit from Google) to be safe

    subject = "Honeypot Alert: Malicious IPs Detected"
    body = "The following IPs were detected as malicious:\n\n" + "\n".join(ip_list)
    body = body.encode("utf-8", errors="ignore").decode("utf-8")

    # Encode body in UTF-8
    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, app_password)
            server.send_message(msg)
            print("Alert email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")
