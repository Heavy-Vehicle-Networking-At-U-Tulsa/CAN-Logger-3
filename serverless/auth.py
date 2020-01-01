import json
import base64
import time

import jwkest
from jwkest.jwk import load_jwks_from_url, load_jwks
from jwkest.jws import JWS
from passlib.hash import pbkdf2_sha256 as passwd

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils

import boto3
import boto3.session as session
from botocore.exceptions import ClientError

from utils import lambdaResponse as response

jws = JWS()

AWS_REGION = "us-east-2"
USER_POOL_ID = "us-east-2_fiNazAdBU"

def auth(event, context):
    """
    Return the plain text session key used to encrypt the CAN Data File
    
    event dictionary input elements:
     - authorized user email 
     - CAN Logger Serial Number
     - CAN Logger File Unique ID (assigned when uploaded to S3)
     - CAN Logger File Session key
    
    Prerequisites:
    The CAN Logger must be provisioned with a securely stored key tied to the
    serial number.
    """
    return response(200, json.dumps({"event": event},indent=4))
    body = json.loads(event['body'])
    try: 
        assert 'serial_number' in body
        assert 'file_uid' in body
        assert 'session_key' in body
    except AssertionError:
        return response(400, "Missing required parameters.")
    
    auth_token = event['request_context']
    if not verifyToken(auth_token):
        return response(400, "auth_token")

    return response(200, json.dumps({"event": event}))
    

def verifyToken(token):
    """
    Decodes a JWS token. If decoding is successful (i.e. the token is valid), then return valid:True otherwise return valid:False
    """
    return True
