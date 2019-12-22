import json
import os
import time
import jwt
from jwt import ExpiredSignatureError, InvalidIssuerError, InvalidIssuedAtError, DecodeError
from passlib.hash import pbkdf2_sha256 as passwd
import boto3
import boto3.session as session
from botocore.exceptions import ClientError

region = 'us-east-2'

def verifyToken(token):
    """
    Decodes a java web token. If decoding is successful (i.e. the token is valid), then return valid:True otherwise return valid:False
    """
    try:
        verified_token = jwt.decode(token, os.environ['JWTSecret'], algorithms=['HS256'], issuer="systems-cyber")
    except (ExpiredSignatureError, InvalidIssuerError, InvalidIssuedAtError, DecodeError) as e:  # noqa: F841
        print("Token verification failed")
        return {"valid": False}
    print("verfied Token: {}".format(verified_token))
    return = {
        "email": verified_token["sub"],
        "scope": verified_token["scope"],
        "token": verified_token,
        "valid": True
    }

def verifyPass(email, password):
    """
    Users with an e-mail and password can be validated.
    """
    client = dbManagement.getDynamoDBClient()
    client = boto3.resource('dynamodb', region_name=region)
    table = client.Table(CANLoggerUsers)
    resp = table.get_item(Key={'email': email})
    if 'Item' in resp:
        print("Found User {}".format(email))
        user = resp['Item']
        try:
            valid = passwd.verify(password, user['passwordHash'])
            if valid:
                return {"token": get_token(email, ["login:user"]),
                        "valid": True
                        }
            else:
                print("Password did not validate.")
        except:
            print("There was an issue when verifying the password.")
    else:
        print("User not found. Looking for {}".format(email))
    return {"valid": False}


def auth(event, context):
    """
    Issue a java web token (JWT) based on a valid password.
    The expected body of the call is
    {
        'username': someone@example.com,
        'password': aValid8CharacterPassword
    }
    Passwords are hidden because the api calls are done using TLS

    """
    body = json.loads(event['body'])
    try: 
        assert 'username' in body
        assert 'password' in body
    except AssertionError:
        return response(400, "Missing required parameters.")
    verify_return = verifyPass(body['username'], body['password'])
    valid = verify_return['valid']  
    if valid:
        token = verify_return['token']
        return response(200, json.dumps({"token": token}))
    else:
        return response(403, "Forbidden: Invalid Username or Password.")
    

def refresh(event, context):
    user = event['requestContext']['authorizer']['sub']
    if user == 'invalidUser':
        return response(403, "Forbidden")
    scope = json.loads(event['requestContext']['authorizer']['scope'])
    token = get_token(user, scope)
    return response(200, json.dumps({"token": token}))


def get_token(email, scope):
    """
    Returns a valid JWT token based on the email/username and scope
    """
    assert isinstance(scope, list)
    token = {
        "iss": "systems-cyber",
        "exp": time.time()+300, #update to last 300 Seconds
        "iat": time.time(),
        "sub": email,
        "scope": scope
    }
    return jwt.encode(token, os.environ['JWTSecret'], algorithm='HS256').decode('ascii')


def parseTokenPolicy(principalId, effect, resource, scope=[], token={}):
    policyDocument = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": "*"
            }
        ]
    }
    context = {
        "sub": principalId,
    }
    if token:
        context["token"] = json.dumps(token)
    if scope:
        context["scope"] = json.dumps(scope)
    policy = {
        "principalId": principalId,
        "policyDocument": policyDocument,
        "context": context
    }
    return policy


def validateAuth(event, context):
    """
    A custom authorizer for AWS API Gateway
    must include as a header:
    Authorization: Bearer firstpartofJWT.middleofJWT.lastpartofJWT
    """
    if(event['type'] == "TOKEN"):
        token = event['authorizationToken'].split()
        valid = False
        if(token[0] == "Bearer"):
            parsedAuth = verifyToken(token[1])
            valid = parsedAuth['valid']
        if(valid):
            print("Token Valid")
            return parseTokenPolicy(parsedAuth['email'],
                                    'Allow',
                                    event["methodArn"],
                                    parsedAuth["scope"],
                                    parsedAuth["token"])
        else:
            return parseTokenPolicy('invalidUser', 
                                    'Deny', 
                                    event["methodArn"])
    else:
        return parseTokenPolicy('invalidUser', 
                                'Deny', 
                                event["methodArn"])
