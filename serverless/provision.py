import json
import base64
import datetime
import hashlib

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import boto3
from botocore.exceptions import ClientError

from utils import lambdaResponse as response
from utils import verify_meta_data_text

import random
import string

cmk_id = "arn:aws:kms:us-east-2:096696900030:key/161b7817-f9b5-444a-87dc-a4d5943f7c1e"

def provision(event,context):
    """
    Read post data to create a new key based on a new device
    """
    body = json.loads(event['body'])
    try: 
        assert 'serial_number' in body
        assert 'device_public_key' in body
    except AssertionError:
        return response(400, "Missing required parameters.")
    try:
        pub_key = base64.b64decode(body['device_public_key'])
        assert len(pub_key) == 128
        device_pub_key_bytes = bytearray.fromhex(pub_key.decode('ascii'))
        serial_number = base64.b64decode(body['serial_number'])
        assert len(serial_number) == 18
        assert len(body['device_label']) == 5
    except:
        return response(400, "Parameters are in the incorrect format.")

    requester_data = event["requestContext"]
    if requester_data["authorizer"]["claims"]["email_verified"]:
        identity_data = event["requestContext"]["identity"]
        print(identity_data)
        ip_address = identity_data["sourceIp"]
        email = requester_data["authorizer"]["claims"]["email"].lower()
    else:
        return response(400, "Email not verified.")
    
    #generate server ECC key pair
    server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_pem_key = server_private_key.private_bytes(
                            encoding = serialization.Encoding.PEM,
                            format = serialization.PrivateFormat.PKCS8,
                            encryption_algorithm = serialization.NoEncryption())
    print(server_pem_key.decode('utf-8'))

    server_public_key = server_private_key.public_key()
    server_public_key_bytes = server_public_key.public_bytes(
        encoding = serialization.Encoding.X962,
        format = serialization.PublicFormat.UncompressedPoint)[1:]
    server_public_key_text = server_public_key_bytes.hex().upper()
    print('server_public_key:')
    print(server_public_key_text)
    
    #Hash device public key and server public key
    device_public_key_hash = hashlib.sha256(device_pub_key_bytes).digest()
    server_public_key_hash = hashlib.sha256(server_public_key_bytes).digest()

    # Generate a data key associated with the CMK
    # The data key is used to encrypt the file. Each file can use its own
    # data key or data keys can be shared among files.
    # Specify either the CMK ID or ARN
    data_key_encrypted, data_key_plaintext = create_data_key(cmk_id)
    if data_key_encrypted is None:
        return False
    print('Created new AWS KMS data key')

    
    # Encrypt the file
    f = Fernet(data_key_plaintext)
    server_pem_key_encrypted = f.encrypt(server_pem_key)

    #Create a random 16 bytes
    choices = string.ascii_letters + string.digits
    rand_pass = b''
    for i in range(16):
    	rand_pass += bytes(random.choice(choices),'ascii')

    #Load Device Public Key and derive shared secret
    device_bytes = b'\x04' + device_pub_key_bytes
    print('device_bytes:')
    print(device_bytes)
    try:
        device_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),device_bytes)
    except ValueError:
        return response(400, "Device Public Key is malformed")
    shared_secret = server_private_key.exchange(ec.ECDH(),device_pub_key)

    #use the first 16 bytes (128 bits) of the shared secret to encrypt the random password
    cipher = Cipher(algorithms.AES(shared_secret[:16]), 
                                   modes.ECB(), 
                                   backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_rand_pass = encryptor.update(rand_pass) + encryptor.finalize()

    #Serialize server private key with password from rand_pass
    server_pem_key_pass = server_private_key.private_bytes(
                            encoding = serialization.Encoding.PEM,
                            format = serialization.PrivateFormat.PKCS8,
                            encryption_algorithm = serialization.BestAvailableEncryption(rand_pass))


    can_logger_dict = {
        'id': serial_number.decode("utf-8"), #72 bit unique id from the ATECC608.
        'device_label': body['device_label'],
        'device_public_key': body['device_public_key'],
        'device_public_key_prov_hash':device_public_key_hash.hex().upper()[:10],
        'server_public_key_prov_hash':server_public_key_hash.hex().upper()[:10],
        'email': email,
        'sourceIp':ip_address,
        'encrypted_data_key': base64.b64encode(data_key_encrypted).decode('utf-8'),
        'encrypted_server_pem_key': base64.b64encode(server_pem_key_encrypted).decode('utf-8'),
        'provision_time': datetime.datetime.now().isoformat().split('.')[0]
        #'password_for_testing': rand_pass.decode('ascii') #Will delete after testing

        }

    #Load the server_public_key, the server_pem_key_pass, and the encrypted_rand_pass
    data_dict = {
    	'server_public_key': base64.b64encode(server_public_key_bytes).decode('ascii'),
    	'server_pem_key_pass':base64.b64encode(server_pem_key_pass).decode('ascii'),
    	'encrypted_rand_pass':base64.b64encode(encrypted_rand_pass).decode('ascii')
    }

    dbClient = boto3.resource('dynamodb', region_name='us-east-2')
    table = dbClient.Table("CANLoggers")
    try:
        ret_dict = table.put_item(
                Item = can_logger_dict,
                ConditionExpression = 'attribute_not_exists(id)'
            )
    except:
        return response(400, "serial number already exists")
    return response(200, data_dict)
    

def create_data_key(cmk_id, key_spec='AES_256'):
    """Generate a data key to use when encrypting and decrypting data

    :param cmk_id: KMS CMK ID or ARN under which to generate and encrypt the
    data key.
    :param key_spec: Length of the data encryption key. Supported values:
        'AES_128': Generate a 128-bit symmetric key
        'AES_256': Generate a 256-bit symmetric key
    :return Tuple(EncryptedDataKey, PlaintextDataKey) where:
        EncryptedDataKey: Encrypted CiphertextBlob data key as binary string
        PlaintextDataKey: Plaintext base64-encoded data key as binary string
    :return Tuple(None, None) if error
    """

    # Create data key
    kms_client = boto3.client('kms')
    try:
        data_response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)
    except ClientError as e:
        print(e)
        return None, None

    # Return the encrypted and plaintext data key
    return data_response['CiphertextBlob'], base64.b64encode(data_response['Plaintext'])   