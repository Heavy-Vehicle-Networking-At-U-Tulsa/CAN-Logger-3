import json
import base64
import boto3
import logging
import sys
import os
import hashlib

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

from utils import verify_meta_data_text
from utils import lambdaResponse as response

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
        email = requester_data["authorizer"]["claims"]["email"]
    else:
        return response(400, "Email not verified.")

    verified = True
    meta_data = meta_data_bytes.decode('ascii').split(",")
    meta_data_dict = {}
    meta_data_dict["datetime"] = meta_data[0] #String of YYYY-MM-DDTHH:MM:SS
    meta_data_dict["CAN0"] = int(meta_data[1]) # CAN Bitrate
    meta_data_dict["CAN1"] = int(meta_data[2]) # CAN Bitrate
    meta_data_dict["filename"] = meta_data[3] # SD Card filename
    meta_data_dict["serial_num"] = meta_data[4].split(":")[1] # Unique ID as a string from the ATECC608 Chip
    meta_data_dict["init_vect"] = meta_data[5].split(":")[1] #string of hex characters as bytes
    meta_data_dict["session_key"] = meta_data[6].split(":")[1] #string of hex characters as bytes
    meta_data_dict["filesize"] = int(meta_data[8].split(":")[1]) # number of bytes
    meta_data_dict["digest"] = meta_data[9].split(":")[1] #string of hex characters as bytes
    meta_data_dict["text_sha_digest"] = meta_data[10].split(":")[1] #string of characters as bytes
    meta_data_dict["signature"] = meta_data[11].split(":")[1] #string of characters as bytes
    meta_data_dict['access_list'] = [] # Will be a json string for a list at some point. 
    meta_data_dict['upload_date'] = ' ' # to be filled in after successful verification of file in S3
    meta_data_dict['uploader'] = email # Attribute who uploaded the file
    meta_data_dict['meta_data'] = user_input_data # User added data 
    
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
    response(200, body)

    s3 = boto3.resource('s3')
    try:
        s3.download_file(Bucket='can-log-files',
                                    Key=meta_data_dict['digest'],
                                    Filename= 'tmp/temp.bin')
    except Exception as e:
        return response(400, "Log file cannot be found in s3 Bucket" + repr(e))

    file_size = os.path.getsize('tmp/temp.bin')
    file_location = 0
    with open('tmp/temp.bin','rb') as file:
        m = hashlib.sha256()
        while file_location<file_size:
            data_buffer = file.read(512)
            file_location+=512
            data_buffer.seek(file_location)
            m.update(data_buffer)
    s3_file_digest = m.digest().hex().upper()
    
    if meta_data_dict["digest"] != s3_file_digest:
        return respnse(400, "Log file hash does not match")

