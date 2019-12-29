import json
import time
import sys
import logging
from ecdsa import VerifyingKey, BadSignatureError, NIST256p
import hashlib
import traceback


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
    
def verify_meta_data_text(raw_line):
    # The data from the serial port comes in as raw bytes, but they are ascii encoded
    parts =  raw_line.split(b',TXT-SHA:')
    logger.debug("Parts after split on TXT-SHA:")
    logger.debug(parts)
    try:
        meta_data_bytes = parts[0]
        sha_and_signature = parts[1].split(b',SIG:')
        text_sha = sha_and_signature[0]
        sha_signature = sha_and_signature[1]
        logger.debug("Bytes to Verify: {}".format(meta_data_bytes))
        logger.debug("Claimed SHA-256: {}".format(text_sha))
        logger.debug("Claimed Signature: {}".format(sha_signature))
        
        m = hashlib.sha256()
        m.update(meta_data_bytes)
        caclulated_sha = m.hexdigest().upper()
        sha_hex = m.digest()
        logger.debug("Calculated SHA_256: {}".format(caclulated_sha))
        if caclulated_sha != text_sha.decode('ascii'):
            logger.debug("SHA 256 Digests in text file doesn't match the calculated value.")
            return False

        public_key_bytes = bytearray.fromhex(meta_data_bytes.split(b'PUB:')[1][:128].decode('ascii'))
        signature_hex = bytearray.fromhex(sha_signature[:128].decode('ascii'))
        
        try:
            vk = VerifyingKey.from_string(bytes(public_key_bytes), curve=NIST256p)
        except:
            logger.debug(traceback.format_exc())
            return False
        try:
            vk.verify_digest(signature_hex, sha_hex)
            logger.debug("good signature")
            return True
        except BadSignatureError:
            logger.debug("BAD SIGNATURE")
            return False
            
    except IndexError:
        logger.debug(traceback.format_exc())
        return False

def get_timestamp(seconds):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(seconds))
    except ValueError:
        return "Not Available"

def lambdaResponse(statusCode,
                   body,
                   headers={},
                   isBase64Encoded=False):
    """
    A utility to wrap the lambda function call returns with the right status code,
    body, and switches.
    """

    # Make sure the body is a json object
    if not isinstance(body, str):
        body = json.dumps(body)
    # Make sure the content type is json
    header = headers
    header["Content-Type"] = "application/json"  
    response = {
        "isBase64Encoded": isBase64Encoded,
        "statusCode": statusCode,
        "headers": header,
        "body": body
    }
    # These print statement create entries in cloudwatch
    print("Response")
    for k, v in response.items():
        print("{}: {}".format(k, repr(v)[:100]))
    return response