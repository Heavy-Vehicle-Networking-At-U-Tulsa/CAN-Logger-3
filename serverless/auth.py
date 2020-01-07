import json
import base64
import boto3
from botocore.exceptions import ClientError

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from utils import lambdaResponse as response

def auth(event, context):
    """
    Return the plain text session key used to encrypt the CAN Data File
    
    event dictionary input elements:
     - CAN Logger Serial Number
     - CAN Logger File Unique ID (assigned when uploaded to S3)
     - CAN Logger File Session key
     - SHA256 digest of the binary file

    Prerequisites:
    The CAN Logger must be provisioned with a securely stored key tied to the
    serial number.
    """
    #load the event body into a dictionary
    body = json.loads(event['body'])

    # Test to be sure the necessary elements are present
    try: 
        assert 'serial_number' in body
        assert 'file_uid' in body
        assert 'session_key' in body
        assert 'digest' in body
    except AssertionError:
        return response(400, "Missing required parameters.")
    file_uid = body['file_uid']

    #Determine the identity of the requester.
    requester_data = event["requestContext"]
    if requester_data["authorizer"]["claims"]["email_verified"]:
    	identity_data = event["requestContext"]["identity"]
    	ip_address = identity_data["sourceIp"]
    	email = requester_data["authorizer"]["claims"]["email"]
    else:
    	return response(400, "Email not verified.")

    # Lookup the data needed from the unique CAN Logger by its serial number
    dbClient = boto3.resource('dynamodb', region_name='us-east-2')
    table = dbClient.Table("CANLoggers")
    try:
        item = table.get_item( 
            Key = {'id': body['serial_number'],} 
        ).get('Item')
    except:
        return response(400, "Unable to retrieve table item.")
    
    # load the device's public key which was stored as a base64 encoded binary
    device_bytes = b'\x04' + base64.b64decode(item['device_public_key'])
    device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),device_bytes)
    
    # Decrypt the data key before using it
    cipher_key = base64.b64decode(item['encrypted_data_key'])
    data_key_plaintext = decrypt_data_key(cipher_key)
    if data_key_plaintext is None:
        return response(400, "Data Key is Not Available")

    # Decrypt the private key for the device
    f = Fernet(data_key_plaintext)
    decrypted_pem = f.decrypt(base64.b64decode(item['encrypted_device_pem_key']))
    
    #load the serialized key into an object
    server_key = serialization.load_pem_private_key(decrypted_pem, 
                                                    password=None, 
                                                    backend=default_backend())
    
    #Derive shared secret
    shared_secret = server_key.exchange(ec.ECDH(),device_public_key)
    session_key = base64.b64decode(body["session_key"])
    
    #use the first 16 bytes (128 bits) of the shared secret to decrypt the data
    cipher = Cipher(algorithms.AES(shared_secret[:16]), 
                                   modes.ECB(), 
                                   backend=default_backend())
    decryptor = cipher.decryptor()
    clear_key = decryptor.update(session_key) + decryptor.finalize()
    
    print("Decrypted Session Key for {} from IP Address {} for file id {}".format(email,ip_address,file_uid))
    
    #return the base64 encoded AES key for that session.
    return response(200, base64.b64encode(clear_key).decode('ascii'))
    
def decrypt_data_key(data_key_encrypted):
    """Decrypt an encrypted data key

    :param data_key_encrypted: Encrypted ciphertext data key.
    :return Plaintext base64-encoded binary data key as binary string
    :return None if error
    """

    # Decrypt the data key
    kms_client = boto3.client('kms')
    try:
        response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)
    except ClientError as e:
        print(e)
        return None

    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response['Plaintext']))