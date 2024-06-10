class EmailTemplates:
    
    @classmethod
    def __getEmailStyle(cls):
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="background-color: #15171e; font-family: Arial, sans-serif; margin: 0; padding: 0; color: #ffffff;">
        <table bgcolor="#15171e" style="background-color:#15171e;background-image:linear-gradient(#15171e,#15171e); width: 100%; min-width: 100%; border-spacing: 0; border-collapse: collapse; margin: 0 auto; word-wrap: break-word; word-break: break-word;">
        <tbody>
        <tr>
        <td bgcolor="#15171e" style="background-color:#15171e;background-image:linear-gradient(#15171e,#15171e); padding: 20px;">
        <table width="600" border="0" cellpadding="0" cellspacing="0" align="center" valign="top" bgcolor="#1a1c23" style="width:600px;min-width:600px;border-spacing:0;border-collapse:collapse;margin:0 auto;word-wrap:break-word;word-break:break-word;background-color:#1a1c23;background-image:linear-gradient(#1a1c23,#1a1c23);">
        <tbody>
        <tr>
        <td style="padding: 20px; background-color: #1a1c23; border: 1px solid #2e3036; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.2);">
        """
    
    @classmethod
    def __getEmailDisclaimer(cls):
        return """
        <!-- Disclaimer -->
        <div style="margin-top: 20px; font-size: 12px; text-align: center; color: #666666;">
            <p>Disclaimer: The WowTasker team is committed to your privacy and security. Please be aware that we will never ask for your personal information, including your username, email, or password, outside of our official ticketing system. If you receive any requests for such information via email, social media, or any other channels not directly linked to our ticketing system, do not respond. These are not authorized by WowTasker and could be phishing attempts. For your safety, always ensure you are communicating through our secure, official channels. If you have any doubts or concerns, please contact us directly through our official website support system.</p>
        </div>
        <div style="margin-top: 20px; font-size: 12px; text-align: center; color: #666666;">
            &copy; 2024 WoWTasker.io. All rights reserved.
        </div>
        </td>
        </tr>
        </tbody>
        </table>
        </td>
        </tr>
        </tbody>
        </table>
        </body>
        </html>
        """

    @classmethod
    def getVerificationEmail(cls, username, code):
        return f"""
        {cls.__getEmailStyle()}
        <title>Verification Code</title>
        <div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
            <h2>Verify Your Email Address</h2>
        </div>
        <div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
            <p style="font-size: 24px; font-weight: bold; color: #ffffff;"> Hello {username},</p>
            <p style="font-size: 16px; color: #ffffff;">Thank you for registering with WoWTasker.io! To complete your registration, please enter the following verification code on our website:</p>
            <p style="font-size: 24px; font-weight: bold; color: #4CAF50; border: 1px dashed #4CAF50; padding: 10px; display: inline-block; margin: 20px 0;">{code}</p>
            <br>
            <p style="font-size: 18px; padding: 10px; display: inline-block; margin: 20px 0;color:#ad1005;"><i>This verification expires in 3 minutes.</i></p>
            <p style="font-size: 16px; color: #ffffff;">If you did not request this code, you can safely ignore this email. Someone else might have typed your email address by mistake.</p>
            <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
        </div>
        <!-- Image Insertion -->
        <div style="text-align: center; margin: 20px 0;">
            <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
        </div>
        {cls.__getEmailDisclaimer()}
        """

    @classmethod
    def getPasswordChangeVerificationEmail(cls, username, code):
        return f"""
        {cls.__getEmailStyle()}
        <title>Password Change Verification Code</title>
        <div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
            <h2>Verify Your Password Change Request</h2>
        </div>
        <div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
            <p style="font-size: 24px; font-weight: bold; color: #ffffff;"> Hello {username},</p>
            <p style="font-size: 16px; color: #ffffff;">We received a request to change your password on WoWTasker.io! To confirm this request, please enter the following verification code on our website:</p>
            <p style="font-size: 24px; font-weight: bold; color: #4CAF50; border: 1px dashed #4CAF50; padding: 10px; display: inline-block; margin: 20px 0;">{code}</p>
            <br>
            <p style="font-size: 18px; padding: 10px; display: inline-block; margin: 20px 0;color:#ad1005;"><i>This verification expires in 3 minutes.</i></p>
            <p style="font-size: 16px; color: #ffffff;">If you did not request this code, you can safely ignore this email. Someone else might have typed your email address by mistake.</p>
            <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
        </div>
        <!-- Image Insertion -->
        <div style="text-align: center; margin: 20px 0;">
            <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
        </div>
        {cls.__getEmailDisclaimer()}
        """

    @classmethod
    def getForgotPasswordEmail(cls, username, code):
        return f"""
        {cls.__getEmailStyle()}
        <title>Forgot Password Verification Code</title>
        <div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
            <h2>Verify Your Forgot Password Request</h2>
        </div>
        <div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
            <p style="font-size: 24px; font-weight: bold; color: #ffffff;"> Hello {username},</p>
            <p style="font-size: 16px; color: #ffffff;">We received a request to reset your password on WoWTasker.io! To confirm this request, please enter the following verification code on our website:</p>
            <p style="font-size: 24px; font-weight: bold; color: #4CAF50; border: 1px dashed #4CAF50; padding: 10px; display: inline-block; margin: 20px 0;">{code}</p>
            <br>
            <p style="font-size: 18px; padding: 10px; display: inline-block; margin: 20px 0;color:#ad1005;"><i>This verification expires in 3 minutes.</i></p>
            <p style="font-size: 16px; color: #ffffff;">If you did not request this code, you can safely ignore this email. Someone else might have typed your email address by mistake.</p>
            <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
        </div>
        <!-- Image Insertion -->
        <div style="text-align: center; margin: 20px 0;">
            <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
        </div>
        {cls.__getEmailDisclaimer()}
        """

    @classmethod
    def getDeleteUserVerificationEmail(cls, username, code):
        return f"""
        {cls.__getEmailStyle()}
        <title>User Deletion Verification Code</title>
        <div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
            <h2>Verify Your User Deletion Request</h2>
        </div>
        <div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
            <p style="font-size: 24px; font-weight: bold; color: #ffffff;"> Hello {username},</p>
            <p style="font-size: 16px; color: #ffffff;">We received a request to delete your account on WoWTasker.io! To confirm this request, please enter the following verification code on our website:</p>
            <p style="font-size: 24px; font-weight: bold; color: #4CAF50; border: 1px dashed #4CAF50; padding: 10px; display: inline-block; margin: 20px 0;">{code}</p>
            <br>
            <p style="font-size: 18px; padding: 10px; display: inline-block; margin: 20px 0;color:#ad1005;"><i>This verification expires in 3 minutes.</i></p>
            <p style="font-size: 16px; color: #ffffff;">If you did not request this code, you can safely ignore this email. Someone else might have typed your email address by mistake.</p>
            <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
        </div>
        <!-- Image Insertion -->
        <div style="text-align: center; margin: 20px 0;">
            <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
        </div>
        {cls.__getEmailDisclaimer()}
        """

    @classmethod
    def getAccountDeletedEmail(cls, username):
        return f"""
        {cls.__getEmailStyle()}
        <title>Account Deleted</title>
        <div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
            <h2>Your Account Has Been Deleted</h2>
        </div>
        <div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
            <p style="font-size: 24px; font-weight: bold; color: #ffffff;">Hello {username},</p>
            <p style="font-size: 16px; color: #ffffff;">Your account has been deleted. You are lost, but not forgotten. If you wish to register again, we would love to have you back at any time.</p>
            <a href="http://wowtasker.io/register" style="font-size: 16px; display: inline-block; background-color: #4CAF50; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 20px 0;">Register Again</a>
            <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
        </div>
        <!-- Image Insertion -->
        <div style="text-align: center; margin: 20px 0;">
            <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
        </div>
        {cls.__getEmailDisclaimer()}
        """

    @classmethod
    def getPaymentConfirmEmail(cls, username, product_name, invoice_id):
        return f"""
        {cls.__getEmailStyle()}
        <title>Payment Confirmation</title>
        <div style="color: #00aeff; margin-bottom: 20px;text-align:center;">
            <h2>Payment Confirmation</h2>
        </div>
        <div style="font-size: 16px; line-height: 1.5; color: #ffffff;">
            <p style="font-size: 24px; font-weight: bold; color: #ffffff;"> Hello {username},</p>
            <p style="font-size: 16px; color: #ffffff;">Thank you for your purchase!</p>
            <p style="font-size: 16px; color: #ffffff;">We have received your payment for {product_name}! Your invoice ID is {invoice_id}. You now have access to the <a href="http://wowtasker.io/downloads">Downloads Page</a></p>
            <p style="font-size: 16px; color: #ffffff;">Please have a look at our <a href="http://wowtasker.io/gettingstarted">Getting Started Guide</a></p>
            
            
            <p style="font-size: 16px; color: #ffffff;">Thank you,<br>WoWTasker.io Team</p>
        </div>
        <!-- Image Insertion -->
        <div style="text-align: center; margin: 20px 0;">
            <img src="http://wowtasker.io/static/logo.png" alt="WoWTasker.io Logo" width="128" height="128" style="margin: 0 auto;">
        </div>
        {cls.__getEmailDisclaimer()}
        """
