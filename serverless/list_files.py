import json
import base64
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

from utils import lambdaResponse as response

from boto3.dynamodb.conditions import Key, Attr

def list_files(event, context):
    """
    Returns a metadata dictionary for files on S3 that have been uploaded by the user.
    """
    requester_data = event["requestContext"]
    if requester_data["authorizer"]["claims"]["email_verified"]:
        email = requester_data["authorizer"]["claims"]["email"].lower()
    else:
        return response(400, "Email not verified.")

    # Lookup the data needed from the unique CAN Logger by its serial number
    dbClient = boto3.resource('dynamodb', region_name='us-east-2')
    table = dbClient.Table("CanLoggerMetaData")
    try:
        records = table.scan( 
            FilterExpression = Attr('uploader').eq(email) | Attr('access_list').contains(email)
        )
    except:
        return response(400, "Unable to retrieve table item.")

    return response(200,records)