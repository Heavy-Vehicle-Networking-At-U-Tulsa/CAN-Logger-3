import boto3
import os
import boto3.session as session
from botocore.exceptions import ClientError

region = 'us-east-1'
endpoint = False #'http://localhost:4569' #False 
s3endpoint = False #'http://localhost:4572'
s3Key = "1234"
s3Secret = "1234"
uploadBucket = "truckcryptuploads" #no caps in URLs for s3
uploadDB = "TruckcryptUploads-"+os.environ['stage']
userDB = "TruckcryptUsers-"+os.environ['stage']
orgDB = "TruckcryptOrgs-"+os.environ['stage']
userOrgDB = "TruckcryptUserOrg-"+os.environ['stage']

def getDynamoDBClient():
    if endpoint:
        client = boto3.resource('dynamodb', region_name=region, endpoint_url=endpoint, aws_access_key_id=s3Key, aws_secret_access_key=s3Secret)
    else:
        client = boto3.resource('dynamodb', region_name=region)
    return client

def getDynamoDBRealClient():
    if endpoint:
        client = boto3.client('dynamodb', region_name=region, endpoint_url=endpoint, aws_access_key_id=s3Key, aws_secret_access_key=s3Secret)
    else:
        client = boto3.client('dynamodb', region_name=region)
    return client

def getS3Client():
    if s3endpoint:
        client = boto3.client('s3', region_name=region, endpoint_url=s3endpoint,aws_access_key_id=s3Key, aws_secret_access_key=s3Secret)
        
    else:
        client = boto3.client('s3', region_name=region) # must have aws config to work normally
    return client



def initS3():
    pass;


def createTableUsers(client):
    client.create_table(AttributeDefinitions=[
        {
            'AttributeName': 'email',
            'AttributeType': 'S'
        } ],
    TableName=userDB,
    KeySchema=[
        {
            'AttributeName': 'email',
            'KeyType': 'HASH'
        }
    ],
    ProvisionedThroughput={
        'ReadCapacityUnits':5,
        'WriteCapacityUnits':5,
    },
    )

def createTableUploads(client):
    client.create_table(AttributeDefinitions=[
        {
            'AttributeName': 'id',
            'AttributeType': 'S'
        }
    ],

    TableName=uploadDB,
    KeySchema=[
        {
            'AttributeName': 'id',
            'KeyType': 'HASH'
        }
    ],
    ProvisionedThroughput={
        'ReadCapacityUnits':5,
        'WriteCapacityUnits':5,
    },
    )

def createTableOrgs(client):
    client.create_table(AttributeDefinitions=[
        {
            'AttributeName': 'slug',
            'AttributeType': 'S'
        }
    ],
    TableName=orgDB,
    KeySchema=[
        {
            'AttributeName': 'slug',
            'KeyType': 'HASH'
        }
    ],
    ProvisionedThroughput={
        'ReadCapacityUnits':5,
        'WriteCapacityUnits':5,
    },
    )

def createTableUserOrg(client):
    client.create_table(AttributeDefinitions=[
        {
            'AttributeName': 'slug',
            'AttributeType': 'S'
        },
        {
            'AttributeName': 'email',
            'AttributeType': 'S'
        }
    ],
    TableName=userOrgDB,
    KeySchema=[
        {
            'AttributeName': 'slug',
            'KeyType': 'HASH'
        },
        {
            'AttributeName': 'email',
            'KeyType': 'RANGE'
        }
    ],
    GlobalSecondaryIndexes=[
        {
            'IndexName':'email',
            'KeySchema': [
                {
                    'AttributeName': 'email',
                    'KeyType': 'HASH'
                },
                {
                    'AttributeName': 'slug',
                    'KeyType': 'RANGE'
                }
            ],
            'Projection':{
                'ProjectionType': 'ALL'
            },
            'ProvisionedThroughput': {
                'ReadCapacityUnits':5,
                'WriteCapacityUnits':5
            }
        }
    ],
    ProvisionedThroughput={
        'ReadCapacityUnits':5,
        'WriteCapacityUnits':5,
    },
    )
