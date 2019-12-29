import json
import time

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