# Serverless Files for Amazon Web Services Deployment

This directory contains the necessary setup scripts an functions to provision and authenticate the encrypted CAN logger 3 data. The strategy makes use of the following AWS features

  1. API Gateway
  2. DynamoDB
  3. Simple Storage Service (S3)
  4. Lambda compute functions

## Window Setup
### AWS Setup
1. Create a login as root. You'll need a credit card to get started.
2. Setup Multi-factor authentication for the root account.
3. Create a new user in IAM as an administrator. Use this user for future work.

### Serverless Setup
See https://serverless.com/framework/docs/providers/aws/guide/credentials/

  1. Setup a programatic admin. Borrowing from the serverless docs:
```
Follow these steps to create an IAM user for the Serverless Framework:

    Login to your AWS account and go to the Identity & Access Management (IAM) page.

    Click on Users and then Add user. Enter a name in the first field to remind you this User is related to the Serverless Framework, like serverless-admin. Enable Programmatic access by clicking the checkbox. Click Next to go through to the Permissions page. Click on Attach existing policies directly. Search for and select AdministratorAccess then click Next: Review. Check to make sure everything looks good and click Create user.

    View and copy the API Key & Secret to a temporary place. You'll need it in the next step.

Note that the above steps grant the Serverless Framework administrative access to your account. While this makes things simple when you are just starting out, we recommend that you create and use more fine grained permissions once you determine the scope of your serverless applications and move them into production.
```
  2. Install Amazon Command Line Interface (CLI). https://docs.aws.amazon.com/cli/latest/userguide/install-windows.html
  3. Add `C:\Program Files\Amazon\AWSCLI\bin` to your path. (type `path` into the start menu and select System Properties. Click on the Environment Variables... button.)
  4. Verify CLI works by entering `aws --version` at the command prompt. An output may look something like this: `aws-cli/1.16.266 Python/3.6.0 Windows/10 botocore/1.13.2`.
  
  5. Create a profile with programatic access. Open a Command Prompt (type `CMD` at the start menu). Be sure you are in your home directory and run `aws configure`. There are four pieces of data needed:
```
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-east-2
Default output format [None]: json
```
  6. Once this is done, there should be a directory in your home called `.aws`. Open this directory and edit the profiles:
    a. We will duplicate the default profile to the `[csu]` profile. The file named config should look like this:
```
[default]
region = us-east-2
output = json

[csu]
region = us-east-2
output = json
```
    b. Similarly, add the `[csu]` profile to the credentials file:
```
[default]
aws_access_key_id = ******************U7
aws_secret_access_key = **************************************RA

[csu]
aws_access_key_id = ******************U7
aws_secret_access_key = **************************************RA
```

  7. Install NodeJS. https://nodejs.org/en/ (Note: installing the extra chocolaty programs take a long time.)
  
  8. Add `C:\Program Files\nodejs` to your path.
  9. Open a new `cmd` window.
  10. Verify node works: `node --version` should produce something like `v12.13.0`. 
  11. Install the serverless package from the command prompt: `npm install -g serverless`. 
  12. Add serverless to your path by adding `%AppData%\npm` to your path variable. Press OK and exit the System Properties Dialog.
  13. Close and reopen the Command Prompt.
  14. Verify serverless is available by entering `sls --version` at the command prompt. You should get something like this in response:
```
Framework Core: 1.55.1
Plugin: 3.2.0
SDK: 2.1.2
Components Core: 1.1.2
Components CLI: 1.4.0
```

Since we are writing in Python, please be sure to include the Requirements.
`sls plugin install -n serverless-python-requirements`

## Linux Setup
### AWS Setup
1. Create a login as root. You'll need a credit card to get started.
2. Setup Multi-factor authentication for the root account.
3. Create a new user in IAM as an administrator. Use this user for future work.

### Serverless Setup
See https://serverless.com/framework/docs/providers/aws/guide/credentials/

  1. Setup a programatic admin. Borrowing from the serverless docs:
```
Follow these steps to create an IAM user for the Serverless Framework:

    Login to your AWS account and go to the Identity & Access Management (IAM) page.

    Click on Users and then Add user. Enter a name in the first field to remind you this User is related to the Serverless Framework, like serverless-admin. Enable Programmatic access by clicking the checkbox. Click Next to go through to the Permissions page. Click on Attach existing policies directly. Search for and select AdministratorAccess then click Next: Review. Check to make sure everything looks good and click Create user.

    View and copy the API Key & Secret to a temporary place. You'll need it in the next step.

Note that the above steps grant the Serverless Framework administrative access to your account. While this makes things simple when you are just starting out, we recommend that you create and use more fine grained permissions once you determine the scope of your serverless applications and move them into production.
```
  2. Install Amazon Command Line Interface (CLI). On Terminal type: `sudo apt install awscli`
  3. Verify CLI works by typing `aws --version` at the Terminal. An output may look something like this: `aws-cli/1.14.44 Python/3.6.9 Linux/5.3.0-28-generic botocore/1.8.48`.
  4. Create a profile with programatic access. Open a Terminal and type `aws configure`. There are four pieces of data needed:
```
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-east-2
Default output format [None]: json
```
    Note: the AWS Access Key ID and Secret Access Key are from the your account Security Credentials in AWS IAM. 
  5. Once this is done, there should be a directory in your home called `.aws`. Open this directory with `cd .aws` and edit the profiles:
    a. We will duplicate the default profile to the `[csu]` profile. The file named config should look like this:
```
[default]
region = us-east-2
output = json

[csu]
region = us-east-2
output = json
```
    b. Similarly, add the `[csu]` profile to the credentials file:
```
[default]
aws_access_key_id = ******************U7
aws_secret_access_key = **************************************RA

[csu]
aws_access_key_id = ******************U7
aws_secret_access_key = **************************************RA
```

  6. Install NodeJS. Information can be found here:https://tecadmin.net/install-latest-nodejs-npm-on-ubuntu/
    First, the system needs to be updated to ensure there is no dependency issues: 
    ```
    sudo apt update
    sudo apt -y upgrade
    ```
    Install nodejs:
    ```
    sudo apt-get install curl
    curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
    sudo apt-get install nodejs
    ```
  7. Verify node works: `node --version` should produce something like `v12.16.1`. 
  8. Install the serverless package from Terminal: `sudo npm install -g serverless`. 
  9. Verify serverless is available by entering `sls --version` at Terminal. You should get something like this in response:
```
Framework Core: 1.64.1
Plugin: 3.4.0
SDK: 2.3.0
Components Core: 1.1.2
Components CLI: 1.4.0
```

## Getting a Serverless Project Started for Window
Be sure to have completed the installation so AWS-CLI, NodeJS, and Serverless are installed. Also, be sure your environment variables have the AWS credentials for the serverless-admin role.

  1. Open a command prompt and change directories to the directory, for example:  `cd Documents\GitHub\CAN-Logger-3\serverless`
  2. Type `serverless` and the program may prompt for a new project:
  ```
Serverless: No project detected. Do you want to create a new one? Yes
Serverless: What do you want to make? AWS Python
Serverless: What do you want to call this project? SecureCANLogger

Project successfully created in 'SecureCANLogger' folder.

You can monitor, troubleshoot, and test your new service with a free Serverless account.

Serverless: Would you like to enable this? No
You can run the “serverless” command again if you change your mind later.
  ```
  3. Press a key to finish.
  4. Copy the files in the newly made directory back over to the current directory since that's where we wanted to work from. These files are .gitignore, handler.py, and serverless.yml.
  4. Type `sls deploy` to push the default function in handler.py to AWS Lambda. You should get something that looks like this: 
 ```
 Serverless: Packaging service...
Serverless: Excluding development dependencies...
Serverless: Creating Stack...
Serverless: Checking Stack create progress...
.....
Serverless: Stack create finished...
Serverless: Uploading CloudFormation file to S3...
Serverless: Uploading artifacts...
Serverless: Uploading service securecanlogger.zip file to S3 (2.36 KB)...
Serverless: Validating template...
Serverless: Updating Stack...
Serverless: Checking Stack update progress...
...............
Serverless: Stack update finished...
Service Information
service: securecanlogger
stage: dev
region: us-east-1
stack: securecanlogger-dev
resources: 5
api keys:
  None
endpoints:
  None
functions:
  hello: securecanlogger-dev-hello
layers:
  None
Serverless: Run the "serverless" command to setup monitoring, troubleshooting and testing.
```
  5. If this worked, then the lambda function will show up in the AWS console. You can now code and deploy by adding functions to `serverless.yml` and deploying them with `sls deploy`

## Getting a Serverless Project Started for Linux
Be sure to have completed the installation so AWS-CLI, NodeJS, and Serverless are installed. Also, be sure your environment variables have the AWS credentials for the serverless-admin role.

  1. Open Terminal and install git:  `sudo apt-get install git`
  2. Make sure you are at a directory you want to clone the clone the github repository.
  3. Clone the CAN-Logger-3 repository: `git clone https://github.com/SystemsCyber/CAN-Logger-3`
  4. Change to serverless branch by `git checkout remotes/origin/serverless`
  5. Change directory to serverless: `cd serverless`
  6. Make sure we have python3.7 and pip installed:
    ```
    sudo apt-get install python3.7
    sudo apt-get install python3-pip
    ```
  7. Since we are writing in Python, please be sure to include the Requirements.
`sudo sls plugin install -n serverless-python-requirements`
  8. You can now code and deploy by adding functions to `serverless.yml` and deploying them with `sls deploy`. A successful deployment will look like this: 
 ```
Serverless: Generated requirements from /home/duyvan/Desktop/CAN-Logger-3/serverless/requirements.txt in /home/duyvan/Desktop/CAN-Logger-3/serverless/.serverless/requirements.txt...
Serverless: Using static cache of requirements found at /home/duyvan/.cache/serverless-python-requirements/4e278019ee5efbe27b17fbb79510073a1c8a007b651c349fb11dde0d59df647f_slspyc ...
Serverless: Packaging service...
Serverless: Excluding development dependencies...
Serverless: Injecting required Python packages to package...
Serverless: Uploading CloudFormation file to S3...
Serverless: Uploading artifacts...
Serverless: Uploading service securecanlogger.zip file to S3 (26.44 MB)...
Serverless: Validating template...
Serverless: Updating Stack...
Serverless: Checking Stack update progress...
......................................
Serverless: Stack update finished...
Service Information
service: securecanlogger
stage: dev
region: us-east-2
stack: securecanlogger-dev
resources: 44
api keys:
  CANLoggerAPIKey: zpKHdP23zEaXQRFKT6Brk4a0qrcoBbxM76bONWge
endpoints:
  GET - https://47tzdaoo6k.execute-api.us-east-2.amazonaws.com/dev/hello
  POST - https://47tzdaoo6k.execute-api.us-east-2.amazonaws.com/dev/auth
  POST - https://47tzdaoo6k.execute-api.us-east-2.amazonaws.com/dev/upload
  POST - https://47tzdaoo6k.execute-api.us-east-2.amazonaws.com/dev/provision
  GET - https://47tzdaoo6k.execute-api.us-east-2.amazonaws.com/dev/list
functions:
  hello: securecanlogger-dev-hello
  auth: securecanlogger-dev-auth
  upload: securecanlogger-dev-upload
  provision: securecanlogger-dev-provision
  list: securecanlogger-dev-list
layers:
  None
Serverless: Removing old service artifacts from S3...
Serverless: Run the "serverless" command to setup monitoring, troubleshooting and testing.
```

## Setting up Key Managment Services (KMS)
1. From the console, select KMS
2. Create a key. For example, we have an alias for a key of `SecureCANLogger`
3. Select just a couple trusted key administrators.
4. Select more roles who can use the key.
5. Once the key is generated, we can use it in our deployment. Add these lines to the serverless file:
```
service: 
  name: securecanlogger
  awsKmsKeyArn: arn:aws:kms:us-east-2:XXXXXXX:key/some-hash-value
```
and
```
functions:
  hello: # this function will OVERWRITE the service level environment config above
    handler: handler.hello
    awsKmsKeyArn: arn:aws:kms:us-east-1:XXXXXX:key/some-hash
```

## Setting up API-Gateway
Simple add http events to the functions in the serverless.yml file.
```
    events:
      - http:
          path: hello
          method: get
```

## Setting up Tracebacks and Error catching. 
This is important to get feedback for running lambda functions

