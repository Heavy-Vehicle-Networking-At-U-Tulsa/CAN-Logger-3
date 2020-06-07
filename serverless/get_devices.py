import boto3
from utils import lambdaResponse as response

def get_devices(event, context):
    """
    Returns a metadata dictionary for the commissioned devices.
    """
    requester_data = event["requestContext"]
    if requester_data["authorizer"]["claims"]["email_verified"]:
        email = requester_data["authorizer"]["claims"]["email"].lower()
    else:
        return response(400, "Email not verified.")

    # Lookup the data needed from the unique CAN Logger by its serial number
    dbClient = boto3.resource('dynamodb', region_name='us-east-2')
    table = dbClient.Table("CANLoggers")
    # records = table.scan()
    # data = records['Items']
    #try:
    attribs = ['id','device_label', 'provision_time','upload_time','upload_ip']
    records = table.scan(
        AttributesToGet = attribs, 
        #FilterExpression = Attr('uploader').eq(email) | Attr('access_list').contains(email)
    )
    data = records['Items']

    while records.get('LastEvaluatedKey') is not None:
        records = table.scan(
            ExclusiveStartKey=records['LastEvaluatedKey'],
            AttributesToGet = attribs, 
            #FilterExpression = Attr('uploader').eq(email) | Attr('access_list').contains(email)
        )
        data.extend(records['Items'])
    #except:
    #    return response(400, "Unable to retrieve table item.")

    return response(200,data)