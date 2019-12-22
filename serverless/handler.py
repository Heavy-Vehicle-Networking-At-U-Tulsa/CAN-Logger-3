import json

from utils import lambdaResponse as response

def hello(event, context):
    body = {
        "message": "Go Serverless v1.0! Your function executed successfully!",
    }

    return response(200, body)

def upload(event, context):
    body = {
        "message": "You've called the upload function",
        "event": event
    }
    return response(200, body)