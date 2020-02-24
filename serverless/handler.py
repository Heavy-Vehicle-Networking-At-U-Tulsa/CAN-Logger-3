import json
import base64
import boto3
import logging
import sys
import hashlib
import time

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

from utils import verify_meta_data_text
from utils import lambdaResponse as response
from utils import get_timestamp


def hello(event, context):
    body = {
        "message": "Go Serverless v1.0! Your function executed successfully!",
    }

    return response(200, body)

def upload(event, context):
    """
    """
    body = json.loads(event['body'])
    meta_data_bytes = base64.b64decode(body['device_data'])
    user_input_data = body['user_input_data']
    data_size = sys.getsizeof(user_input_data) 
    '''
    try:
        assert isInstance(user_input_data, dict) #make it a dict
        assert data_size < 5000 # make sure it's not too big
    except AssertionError:
        return response(400, "user_input_data is inappropriate. {} bytes".format(data_size))
    ''' 


    requester_data = event["requestContext"]
    if requester_data["authorizer"]["claims"]["email_verified"]:
        email = requester_data["authorizer"]["claims"]["email"].lower()
    else:
        return response(400, "Email not verified.")

    verified = True
    meta_data = meta_data_bytes.decode('ascii').split(",")
    meta_data_dict = {}
    meta_data_dict["datetime"] = meta_data[0] #String of YYYY-MM-DDTHH:MM:SS
    meta_data_dict["CAN0"] = meta_data[1] # CAN Bitrate
    meta_data_dict["CAN1"] = meta_data[2] # CAN Bitrate
    meta_data_dict["filename"] = meta_data[3] # SD Card filename
    meta_data_dict["serial_num"] = meta_data[4].split(":")[1] # Unique ID as a string from the ATECC608 Chip
    meta_data_dict["init_vect"] = meta_data[5].split(":")[1] #string of hex characters as bytes
    meta_data_dict["session_key"] = meta_data[6].split(":")[1] #string of hex characters as bytes
    meta_data_dict["filesize"] = meta_data[8].split(":")[1] # number of bytes
    meta_data_dict["digest"] = meta_data[9].split(":")[1] #string of hex characters as bytes
    meta_data_dict["text_sha_digest"] = meta_data[10].split(":")[1] #string of characters as bytes
    meta_data_dict["signature"] = meta_data[11].split(":")[1] #string of characters as bytes
    meta_data_dict["access_list"] = [] #List of email addresses who have view and download access to the file 
    meta_data_dict["upload_date"] = ' ' # to be filled in after verification of file in S3
    meta_data_dict["uploader"] = email # Attribute who uploaded the file
    meta_data_dict["meta_data"] = user_input_data # User added data
    meta_data_dict["verify_status"] = ' '# to be filled in after verification of file in S3
    meta_data_dict["download_log"] = [] #Log the identity of the user and the time when the file is downloaded
    
    # newUUID = uuid.uuid4()
    # meta_data_dict["id"] = newUUID.hex

    #Verify metadata integrity
    dbClient = boto3.resource('dynamodb', region_name='us-east-2')
    table = dbClient.Table("CANLoggers")
    try:
        item = table.get_item(
            Key = {'id': meta_data_dict["serial_num"],}
            ).get('Item')
    except:
        return response(400, "Serial number not found.")

    device_public_key_server = base64.b64decode(item['device_public_key']).decode('ascii')
    device_public_key_device = meta_data[7].split(":")[1]

    if device_public_key_device != device_public_key_server:
        return response(400, "Public key from metadata does not match the one from server")

    if not verify_meta_data_text(meta_data_bytes):
        return response(400, "Metadata failed to verify.")

    if meta_data_dict["session_key"] == '00000000000000000000000000000000':
        return respones(400, "File is rejected due to invalid encrypted session key")
    
    #Send response 
    table = dbClient.Table("CanLoggerMetaData")
    try:
        table.put_item(
            Item=meta_data_dict,
            ConditionExpression = 'attribute_not_exists(digest)'
        )
    except Exception as e:
        return response(400, "Hash Digest already exists or data is missing. " + repr(e))
    
    client = boto3.client('s3', region_name='us-east-2')
    signedURL = client.generate_presigned_post(Bucket='can-log-files',
                                               Key=meta_data_dict["digest"]
                                              )
    body = {"upload_link": signedURL}
    return response(200, body)


def verify_upload(event,context):

    body = json.loads(event['body'])
    meta_data_bytes = base64.b64decode(body['device_data'])
    meta_data = meta_data_bytes.decode('ascii').split(",")

    #Verify metadata integrity
    dbClient = boto3.resource('dynamodb', region_name='us-east-2')
    table = dbClient.Table("CANLoggers")
    meta_table = dbClient.Table("CanLoggerMetaData")
    try:
        item = table.get_item(
            Key = {'id': meta_data[4].split(":")[1],}
            ).get('Item')
    except:
        return response(400, "Serial number not found.")

    device_public_key_server = base64.b64decode(item['device_public_key']).decode('ascii')
    device_public_key_device = meta_data[7].split(":")[1]

    if device_public_key_device != device_public_key_server:
        return response(400, "Public key from metadata does not match the one from server")

    if not verify_meta_data_text(meta_data_bytes):
        return response(400, "Metadata failed to verify.")
    
    #Verify log file integrity 
    s3 = boto3.resource('s3')
    digest_from_metadata = meta_data[9].split(":")[1]
    try:
        obj = s3.Object('can-log-files',digest_from_metadata)
    except Exception as e:
        return response(400, "Log file cannot be found in s3 Bucket" + repr(e))

    body = obj.get()['Body'].read()
    s3_file_digest = hashlib.sha256(body).digest().hex().upper()

    str_time = get_timestamp(time.time())

    if not digest_from_metadata == s3_file_digest:
        meta_table.update_item(
            Key = {'digest':s3_file_digest},
            UpdateExpression = "SET verify_status= :var1, upload_date= :var2",
                ExpressionAttributeValues = {
                    ':var1': 'Not Verified',
                    ':var2': str_time
            },)
        return response(400,"Log file hash does not match")
    else:
        meta_table.update_item(
                Key = {'digest':s3_file_digest},
                UpdateExpression = "SET verify_status= :var1, upload_date= :var2",
                ExpressionAttributeValues = {
                    ':var1': 'Verified',
                    ':var2': str_time
                },)

    return response(200, "Successfully Verify Log File and Metadata!")