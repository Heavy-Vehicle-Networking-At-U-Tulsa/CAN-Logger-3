import json
import base64
import boto3
import logging
import sys
import hashlib

from utils import verify_meta_data_text
from utils import lambdaResponse as response


def share(event, context):
    """
    Change access_list in CanLoggerMetaData table based on user input
    
    event dictionary input elements:
     - share or revoke option
     - email address
     - digest of the file
    """
    body = json.loads(event['body'])

    # Test to be sure the necessary elements are present
    try:
        assert 'option' in body 
        assert 'email_access' in body
        assert 'digest' in body
    except AssertionError:
        return response(400, "Missing required parameters.")

    #Determine the identity of the requester.
    requester_data = event["requestContext"]
    if requester_data["authorizer"]["claims"]["email_verified"]:
        email = requester_data["authorizer"]["claims"]["email"]
    else:
        return response(400, "Email not verified.")

    #Look up the data
    dbClient = boto3.resource('dynamodb', region_name='us-east-2')
    table = dbClient.Table("CanLoggerMetaData")
    try:
        item = table.get_item(
            Key = {'digest': body['digest'],}
            ).get('Item')
    except:
        return response(400, "File digest not found.")

    #Check if email is the uploader
    if not email == item['uploader']:
        return response(400, "You do not have permission to share or revoke access to the selected file.")

    access_list = item['access_list']

    if body['option'] == 'Share':
        access_list.append(body['email_access'])
    else:
        if body['email_access'] in access_list:
            index = access_list.index(body['email_access'])
            access_list.pop(index)
        else:
            return response(400,"There is no {} in access list to revoke access.".format(body['email_access']))

    table.update_item(
        Key = {'digest':body['digest']},
        UpdateExpression = 'SET access_list= :var',
        ExpressionAttributeValues = {':var':access_list},)

    #response
    if body['option'] == 'Share':
        return response(200, "{} has been added to access list.".format(body['email_access']))
    else:
        return response(200, "{} has been revoked from access list.".format(body['email_access']))
