import smtplib
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr

from .EmailTemplates import EmailTemplates


class EmailHandler:
    
    @classmethod
    def __sendemail(cls, email,subject,body):
        sender = 'noreply@wowtasker.io'
        sender_title = "WoWTasker"
        recipient = email

        # Create message
        msg = MIMEText(body, 'html', 'utf-8')
        msg['Subject'] =  Header(subject, 'utf-8')
        msg['From'] = formataddr((str(Header(sender_title, 'utf-8')), sender))
        msg['To'] = recipient

        # Create server object with SSL option
        # Change below smtp.zoho.com, corresponds to your location in the world. 
        # For instance smtp.zoho.eu if you are in Europe or smtp.zoho.in if you are in India.
        server = smtplib.SMTP_SSL('smtp.zoho.com', 465)

        # Perform operations via server
        server.login('jimkramer3779@gmail.com', 'Bogodin1!')
        server.sendmail(sender, [recipient], msg.as_string())
        server.quit()

    @classmethod
    def sendVerificationEmail(cls, email, username, code):
        cls.__sendemail(email, "Your WoWTasker.io Registration Verification Code", EmailTemplates.getVerificationEmail(username, code))

    @classmethod
    def sendPasswordChangeVerificationEmail(cls, email, username, code):
        cls.__sendemail(email, "Your WoWTasker.io Registration Verification Code", EmailTemplates.getPasswordChangeVerificationEmail(username, code))

    @classmethod
    def sendForgotPasswordEmail(cls, email, username, code):
        cls.__sendemail(email, "Your WoWTasker.io Registration Verification Code", EmailTemplates.getForgotPasswordEmail(username, code))

    @classmethod
    def sendDeleteUserVerificationEmail(cls, email, username, code):
        cls.__sendemail(email, "Your WoWTasker.io Registration Verification Code", EmailTemplates.getDeleteUserVerificationEmail(username, code))

    @classmethod
    def sendAccountDeletedEmail(cls, email, username):
        cls.__sendemail(email, "Your WoWTasker.io Registration Verification Code", EmailTemplates.getAccountDeletedEmail(username))

    @classmethod
    def sendPaymentConfirmEmail(cls, email, username, product_name, invoice_id):
        cls.__sendemail(email, "Your WoWTasker.io Registration Verification Code", EmailTemplates.getPaymentConfirmEmail(username, product_name, invoice_id))
