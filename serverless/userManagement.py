import json
import os
import time
import base64
import boto3
import re
import traceback
import requests
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from passlib.hash import pbkdf2_sha256 as passwd
from utils import lambdaResponse as response

def create(event, context):
    """
    The create function is called with a json body with the following key
    value pairs:
        {
            "email":user@example.com,
            "reset":False
        }
    The email parameter is the username for the user. This should  be a valid email
    for the verification.

    If the email does not exist, then the user is entered into the data table and a
    verification code is sent to the use.

    If the email alreay exists, then a new verification code is sent to the user.
    """
    try:
        body = json.loads(event['body'])
        email = body['email']
        captcha_result = body['captchaResponse']
        agreement = body['agreement']
    except:  # noqa: E722
        print(traceback.format_exc())
        return response(400, "Invalid Body")
    if agreement != 'yes':
        print(body)
        return response(403, "You must agree to the terms and conditions of this service.")
    print("captcha_result from main body: {}".format(captcha_result))
    captcha_verify = verify_recaptcha(captcha_result)
    if not captcha_verify:
        return response(400, "Invalid Recaptcha Response")
    print("Trying to create user: {}".format(email))
    if "@" not in email or "." not in email:
        return response(400, 'Invalid Email')
    email_token = base64.b64encode(os.urandom(16)).decode('ascii')
    client = dbManagement.getDynamoDBClient()
    table = client.Table(dbManagement.userDB)
    resp = table.get_item(Key={'email': email})
    if 'Item' in resp:
        print("User Already Exists")
        reset_count = resp["Item"]['token_creation_count'] + 1
    else:
        reset_count = 0
    if 'noLambda' in event:
        print('Copy this into your application ------>  email_token: ' + email_token)
        email_success = 'Not Used'
    else:
        print('This token was just emailed: ' + email_token)
        print('There have been {} requests for an email token.'.format(reset_count))
        email_success = send_registration_email({'email': email, 'email_token': email_token})
    table.put_item(
        Item={
            'email': email,
            'email_token': email_token,
            'token_create_time': int(time.time()),  # Needed for tokens to expire.
            'token_creation_count': reset_count,  # Use this to see how many times people need to reset.
            'scope': ['validate:user'],
            'org_slugs': [], #Keep track of the org tied to this user as an admin
            'org_limit': 5 # Keep individual users from creating too many orgs
            # TODO: Add secret for 2FA
        }
    )
    if email_success:
        return response(200, json.dumps({'message': "Account Successfully Created or Renewed."}))
    else:
        return response(400, "Account Created or Renewed but there was a failure in sending a verification code. Please contact support.")
    

def updatePassword(event, context):
    """
    A user can set or update his/her passsword.
    A new password is accepted when using a 1-time, 24 hour token.
    A password is changed with either the old password or an email token.
    The event body should look something like this:
    {
        "oldPassword": oldpassword
        "newPassword": passWORD123!@#
    }

    The new password must be well formed with 8 characters.

    Alternatively, an email token can be used to create a new password.
    The email token will be a query string along with the userame. The
    query string is embedded in the URL.
    {
        "newPassword": passWORD123!@#
    }
    """
    try:
        body = json.loads(event['body'])
        newPassword = body['newPassword']
        # enforce some password strength.
        if len(newPassword) < 8:
            print("Password should be 8 or more characters")
            return response(400, "Password needs to be 8 or more characters")
        params = event["queryStringParameters"]
        if 'email_token' in params:
            email = params['email']
            oldPassword = False
        else:
            oldPassword = body['oldPassword']
            try:
                # A valid user is required to update the password.
                email = event['requestContext']['authorizer']['sub']
            except:  # noqa: E722
                print(traceback.format_exc())
                return response(400, "Invalid Authorizer")
    except:  # noqa: E722
        print(traceback.format_exc())
        return response(400, "Invalid Body")
    client = dbManagement.getDynamoDBClient()
    table = client.Table(dbManagement.userDB)
    resp = table.get_item(Key={'email': email})
    if 'Item' in resp:
        print("Found user {}".format(email))
        user = resp['Item']
        print(user)
        if oldPassword:
            if 'passwordHash' in user:
                print("User password found, verifying")
                valid = passwd.verify(oldPassword, user['passwordHash'])
                if valid:
                    table.update_item(
                        Key={'email': email},
                        UpdateExpression="set passwordHash = :newPassword",
                        ExpressionAttributeValues={
                            ":newPassword": passwd.hash(newPassword)
                        },
                        ReturnValues="UPDATED_NEW"
                    )
                    return response(204, json.dumps({'message': "Updated Password"}))
                else:
                    return response(403, "Invalid Password")
            else:
                return response(400, "Missing password record or email token.")
        # Run these commands if oldPassword is False (i.e. a mail token is present)
        print("E-mail token is present, setting password.")
        if "email_token" not in user:
            return response(400, "Missing Token")
        if len(user["email_token"]) <= 1:
            return response(403, "Token was already used")
        if (int(time.time()) - int(user["token_create_time"])) > 24*3600:
            return response(403, "Token Expired")
        if params['email_token'] == user["email_token"]:
            print("Token Verified")
            table.update_item(
                Key={'email': email},
                UpdateExpression=("set passwordHash = :newPassword, " +
                                  "email_token = :newToken"),
                ExpressionAttributeValues={
                    ":newPassword": passwd.hash(newPassword),
                    ":newToken": "1"  # Make it 1 character to show it's been used.
                    },
                ReturnValues="UPDATED_NEW"
            )
            return response(204, json.dumps({'message': "Created New Password Hash"}))
        else:
            return response(403, "Forbidden. Invalid Email Token.")
    else:
        return response(400, "User does not exist")


def getOrgs(event, context):
    user = event['requestContext']['authorizer']['sub']
    if user == 'invalidUser':
        return response(403, "Forbidden")
    client = dbManagement.getDynamoDBClient()
    table = client.Table(dbManagement.userOrgDB)
    resp = table.query(
        IndexName='email',
        KeyConditionExpression=Key('email').eq(user)
    )
    orgs = []
    for org in resp['Items']:
        orgs.append(org['slug'])
    return response(200, json.dumps({"orgs": sorted(orgs)}))


def send_registration_email(event, context={}):
    email = event["email"]
    email_token = event["email_token"]
    SENDER = "admin@truckcrypt.com"
    RECIPIENT = email
    SUBJECT = 'TruckCRYPT Account Verification'
    BODY_HTML = ("""<!DOCTYPE html>
<html>
    <head>
        <title>TruckCRYPT Account Verification</title>
    </head>
    <body>
        <p>
            Thank you for signing up for the TruckCRYPT Software Service.
        </p>
        <p>
            To verify your e-mail address, please navigate to 
            <a href=https://truckcrypt.com/validate.html>
                https://truckcrypt.com/validate.html
            </a>
            and enter the following 24 character validation token into the dialog box.
        </p>
        <p>
            {}
        </p>
        <p>
            or click on the following link:
        </p>
        <p>
            <a href=https://truckcrypt.com/validate.html?email={}&token={}>
                https://truckcrypt.com/validate.html?email={}&token={}
            </a>
        </p>
        <p>
            Once you are logged in, you can download the TruckCRYPT software from the subscription page.
        </p>
    </body>
</html>
""".format(email_token,email,email_token,email,email_token)
    )
    
    BODY_TEXT = ("""Thank you for signing up for the TruckCRYPT Software Service.\n\
To verify your e-mail address, please navigate to \n\n

https://truckcrypt.com/validate.html\n\n

and enter the following 24 character validation token into the dialog box.\n\n
{}\n\n
Once you are logged in, you can download the TruckCRYPT software from the subscription page.
""".format(email_token)
    )
                 
    CHARSET = "UTF-8"
    client = boto3.client('ses')
    # Try to send the email.
    try:
        # Provide the contents of the email.
        ses_response = client.send_email(
            Destination={
                'ToAddresses': [
                    RECIPIENT,
                ],
                'CcAddresses': [
                    'info@synercontechnologies.com',
                ]
            },
            Message={
                'Body': {
                    'Text': {
                        'Charset': CHARSET,
                        'Data': BODY_TEXT,
                    },
                    'Html': {
                        'Charset': CHARSET,
                        'Data': BODY_HTML,
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': SUBJECT,
                },
            },
            Source=SENDER,
            # If you are not using a configuration set, comment or delete the
            # following line
            # ConfigurationSetName=CONFIGURATION_SET,
        )
        print("SES_response: {}".format(ses_response))
        return True
    # Display an error if something goes wrong.
    except:
        print(traceback.format_exc())
    return False

def verify_recaptcha(validation_token):
    if 'TRUCKCRYPT_RECAPTCHA' in os.environ:
        print("Sending captchaResponse of {}".format(validation_token))
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            "secret": os.environ['TRUCKCRYPT_RECAPTCHA'],
            "response": validation_token
        })
        print("Recaptcha responded with a status code of {}".format(r.status_code))
        print("Recaptcha text: {}".format(r.text.replace('\n',' ').replace('\r',''))) #Put log entry into one line
        if r.status_code == 200:
            response = json.loads(r.text)
            if response['success']:
                return True
        return False
    return True
