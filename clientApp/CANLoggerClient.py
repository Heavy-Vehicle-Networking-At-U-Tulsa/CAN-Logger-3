# !/bin/env/python
from PyQt5.QtWidgets import (QMainWindow,
                             QWidget,
                             QTreeView,
                             QMessageBox,
                             QFileDialog,
                             QLabel,
                             QSlider,
                             QCheckBox,
                             QLineEdit,
                             QVBoxLayout,
                             QApplication,
                             QPushButton,
                             QTableWidget,
                             QTableView,
                             QTableWidgetItem,
                             QScrollArea,
                             QAbstractScrollArea,
                             QAbstractItemView,
                             QSizePolicy,
                             QGridLayout,
                             QGroupBox,
                             QComboBox,
                             QAction,
                             QDockWidget,
                             QDialog,
                             QFrame,
                             QDialogButtonBox,
                             QInputDialog,
                             QProgressDialog,
                             QTabWidget)
from PyQt5.QtCore import Qt, QTimer, QAbstractTableModel, QCoreApplication, QSize
from PyQt5.QtGui import QIcon

import boto3
import botocore
from botocore.config import Config

import requests
import threading
import queue
import datetime
import time
import base64
import zipfile
import sys
import struct
import json
import random
import os
import traceback
import logging
import jwkest
from jwkest.jwk import load_jwks_from_url, load_jwks
from jwkest.jws import JWS

import serial
import serial.tools.list_ports

jws = JWS()

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.DEBUG)

AWS_REGION = "us-east-2"
API_ENDPOINT = r"https://47tzdaoo6k.execute-api.us-east-2.amazonaws.com/dev/"
APP_CLIENT_ID = "58tl1drhvqtjkmhs69inh7l1t3"
USER_POOL_ID = "us-east-2_fiNazAdBU"

class CANLogger(QMainWindow):
    def __init__(self):
        super(CANLogger, self).__init__()
        try:
            self.API_KEY = os.environ["CANLogger_API_KEY"]
        except:
            logger.critical(traceback.format_exc())
            QMessageBox.warning(self,"Missing API Key","Please contact Jeremy Daily at Colorado State University to obtain an API key for this application.")
        
        self.statusBar().showMessage("Welcome to the CANLogger App.")

         # Build common menu options
        menubar = self.menuBar()

        #####################
        # FILE
        #####################
        file_menu = menubar.addMenu('&File')
        file_toolbar = self.addToolBar("File")
        
        new_file = QAction(QIcon(r'icons/icons8_New_Ticket_48px.png'), '&Upload', self)
        new_file.setShortcut('Ctrl+U')
        new_file.setStatusTip('Upload current file.')
        new_file.triggered.connect(self.upload_file)
        file_menu.addAction(new_file)
        file_toolbar.addAction(new_file)

        user_menu = menubar.addMenu('&User')
        login = QAction(QIcon(r'icons/new_icon.png'), '&Login', self)
        login.setShortcut('Ctrl+L')
        login.setStatusTip('Upload current file.')
        login.triggered.connect(self.login)
        user_menu.addAction(login)
        file_toolbar.addAction(login)

        hello = QAction(QIcon(r'icons/test_icon.png'), '&Hello', self)
        hello.setShortcut('Ctrl+H')
        hello.setStatusTip('Test Endpoint Authorization.')
        hello.triggered.connect(self.hello)
        user_menu.addAction(hello)
        file_toolbar.addAction(hello)

        #####################
        # LOGGER
        #####################
        logger_menu = menubar.addMenu('&Logger')
        connect_logger = QAction(QIcon(r'icons/connect_icon.png'), 'C&onnect', self)
        connect_logger.setShortcut('Ctrl+o')
        connect_logger.setStatusTip('Connect a CAN Logger through USB.')
        connect_logger.triggered.connect(self.connect_logger_by_usb)
        logger_menu.addAction(connect_logger)
        file_toolbar.addAction(connect_logger)

        self.setWindowTitle("CAN Logger Client Application")
        
        self.signed_file_metadata = None
        self.access_token         = None
        self.identity_token       = None
        self.refresh_token        = None
        self.connected = False

        self.show() 

    def connect_logger_by_usb(self):
        items =[] 
        for device in serial.tools.list_ports.comports():
            items.append("{} - {}".format(device.device, device.description))
        print(items)
        com_port, okPressed = QInputDialog.getItem(self, "Select COM Port","CAN Logger USB Serial Port:", items, 0, False)
        if okPressed and com_port:
            logger.debug("Selected: {}".format(com_port))
            self.comport = com_port.split('-')[0].strip()
        else:
            return
        logger.debug("Trying to connect USB serial.")
        try:
            self.ser.close()
            del self.ser
        except AttributeError:
            pass

        try:
            self.ser = serial.Serial(self.comport, timeout=2)
            self.ser.set_buffer_size(rx_size = 2147483647, tx_size = 2000)
            self.connected = True
            logger.debug("Connected to Serial Port.")
            self.list_device_files()
            return True
        except serial.serialutil.SerialException:
            logger.debug(traceback.format_exc())
            self.connected = False
            if "PermissionError" in repr(traceback.format_exc()):
                QMessageBox.information(self,"USB Status","The port {} is already in use. Please unplug and replug the unit.".format(self.comport))
            else:
                self.connected = False
                return False
    
    def list_device_files(self):
        while not self.connected:
            if self.connect_logger_by_usb() is None:
                return
        self.ser.reset_input_buffer()
        self.ser.write(b'LS A\n')
        response=[]
        ret_val = self.ser.read_until(b'\r\n')
        while len(ret_val) > 0:
            response.append(ret_val.decode('ascii').strip().split())
            ret_val = self.ser.read_until(b'\r\n')    
        logger.debug(response)
        latest_file_name = ''
        latest_file_size = 0
        for line in response:
            logger.debug(line)
            latest_file_name = line[3]
            latest_file_size = int(line[2])
        
        logger.debug("Downloading {} bytes from {}".format(latest_file_size,latest_file_name))    
        if len(latest_file_name) > 4 and latest_file_size > 400:
            #self.ser.timeout = 10
            #send the command to the Logger to download data
            self.ser.write(b'BIN ' + bytes(latest_file_name[:-3]+"txt",'ascii') + b'\n') 
            self.meta_data = self.ser.read(latest_file_size).decode('ascii').split(",")
            
            logger.debug("file meta_data:") 
            logger.debug("{}".format(self.meta_data)) 
            binfile_size = int(self.meta_data[8].split(":")[1])
            filename = self.meta_data[3]
            logger.debug("Downloading {} bytes of {}".format(binfile_size,filename))
            
            self.ser.reset_input_buffer()
            self.ser.write(b'BIN ' + bytes(latest_file_name[:-3]+"bin",'ascii') + b'\n')  
            self.encrypted_binary = b''
            start_time = time.time()
            while (len(self.encrypted_binary) <= binfile_size) and (time.time()-start_time < 15):
                i = max(1, min(2048, self.ser.in_waiting))
                new_data = self.ser.read(i)
                self.encrypted_binary += new_data
                print(len(new_data))
            
            logger.debug("encrypted_binary:") 
            logger.debug("{}...{}".format(self.encrypted_binary[:100],self.encrypted_binary[-100:]))     

    def hello(self):
        """
        This is a test routine to test the connectivity and authentication for the AWS API.
        Success brings up a dialog box when the correct API key is used.
        """
        # define the endpoint URL corresponding the the AWS API Gateway
        url = API_ENDPOINT + "hello"
        header = {"x-api-key": self.API_KEY}
        try:
            r = requests.get(url, headers=header)
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self,"Connection Error","The there was a connection error when connecting to\n{}\nPlease try again once connection is established".format(url))
            return
        logger.debug(r.status_code)
        if r.status_code == 200: #This is normal return value    
            logger.debug(r.json())
            QMessageBox.information(self,"Success","The server responded with code 200:\n{}".format(r.json()))
        else: #Something went wrong
            logger.debug(r.text)
            QMessageBox.warning(self,"Connection Error","The there was an error:\n{}".format(r.text))
        
    def login(self):
        """
        Get a password from the user with a dialog box and submit it.
        Returns a token for further user authentication.
        """
        self.user = 'jeremy.daily@colostate.edu'
        self.user, okPressed = QInputDialog.getText(self, "Username","Username (e-mail):", QLineEdit.Normal, self.user)
        if not okPressed:
            return
        if self.user == '':
            return

        try:
            with open('password.txt','r') as f:
                stored_password = f.read()
            pass_word_saved = True
        except:
            stored_password = ''
            pass_word_saved = False
        password, okPressed = QInputDialog.getText(self, "Password","Input password for \n{}".format(self.user), QLineEdit.Password, stored_password)
        if not okPressed:
            return
        if password == '':
            return
        if stored_password == password:
            pass_word_saved == True
        else:
            pass_word_saved == True

        #https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.initiate_auth
        post_data={
            "AuthParameters" : {
                "USERNAME" : self.user,
                "PASSWORD" : password
               },
               "AuthFlow" : "USER_PASSWORD_AUTH",
               "ClientId" : APP_CLIENT_ID
            }
        url = "https://cognito-idp.us-east-2.amazonaws.com"
        header = {}
        header["Content-Type"]= "application/x-amz-json-1.1"
        header["X-Amz-Target"]= "AWSCognitoIdentityProviderService.InitiateAuth"
        try:
            r = requests.post(url, json=post_data, headers=header)
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self,"Connection Error","The there was a connection error when connecting to\n{}\nPlease try again once connection is established".format(url))
            return
        logger.debug(r.status_code)
        if r.status_code == 200: #This is normal return value
            response_data = r.json()
            for k,v in response_data["AuthenticationResult"].items():
                logger.debug("{}: {}".format(k,v))
            self.access_token = response_data["AuthenticationResult"]["AccessToken"]
            with open("access_token.json",'w') as fp:
                json.dump(self.access_token,fp)
            self.identity_token = response_data["AuthenticationResult"]["IdToken"]
            with open("identity_token.json",'w') as fp:
                json.dump(self.identity_token,fp)
            self.refresh_token = response_data["AuthenticationResult"]["RefreshToken"]
            self.decode_jwt()
            if not pass_word_saved:
                _password, okPressed = QInputDialog.getText(self, "Save Password","DANGER: Do you want to save your clear text password for \n{}? Press OK to save.".format(self.user), QLineEdit.Password, password)
                if okPressed:
                    with open('password.txt','w') as f:
                        f.write(password)  
        else: #Something went wrong
            logger.warning("There was an issue with the web response.")
            logger.debug(r.text)
            try:
                with open("identity_token.json",'r') as fp:
                    self.identity_token = json.load(fp)
                with open("access_token.json",'r') as fp:
                    json.load(self.access_token,fp)
                self.decode_jwt()
            except:
                logger.debug(traceback.format_exc())
                self.access_token = None
                self.identity_token = None
        
    def decode_jwt(self):
        """
        Validate and decode the web token from the Amazon Cognito.
        Stores the public key needed to decrypt the token.
        Returns 
        """
        if self.access_token is None:
            self.login()
        if self.identity_token is None:
            self.login()

        url="https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(AWS_REGION,USER_POOL_ID)
        try:
            r = requests.get(url)
            logger.debug(r.status_code)
            key_set = load_jwks(r.text)
            with open("keys.jwks", "w") as f:
                f.write(r.text)  
        except:
            logger.debug(traceback.format_exc())
            try:
                with open("keys.jwks") as fp:
                    key_set = load_jwks(fp.read())
            except:
                message = "There is no local public key for the Authorization. Please connect to the Internet and try again." 
                message+="\n"+traceback.format_exc()
                logger.warning(message)
                QMessageBox.warning(self,"No Public Key",message)
                return False
        try:
            plain_text = jws.verify_compact(self.access_token, keys=key_set)
            logger.debug("\nAccess Token:")
            logger.debug(plain_text)

            plain_text_dict = jws.verify_compact(self.identity_token, keys=key_set)
            logger.debug("\nID Token:")
            logger.debug(plain_text_dict)
            self.user_id = plain_text_dict['sub']
            self.user_email = plain_text_dict['email']
            return True
        except:
            message = "There was an issue in decoding and verifying the web token." 
            message+="\n"+traceback.format_exc()
            logger.warning(message)
            QMessageBox.warning(self,"Invalid Token",message)
            return False

    def upload_file(self):
        if not self.decode_jwt():
            message = "A valid webtoken is not available to upload."
            logger.warning(message)
            QMessageBox.warning(self,"Invalid Token",message)
            return

        url = API_ENDPOINT + "upload"
        data = {"meta_data":self.signed_file_metadata}
        header = {}
        header["x-api-key"] = self.API_KEY #without this header, the API Gateway will return a 403: Forbidden message.
        header["Authorization"] = self.identity_token #without this header, the API Gateway will return a 401: Unauthorized message
        try:
            r = requests.post(url, json=data, headers=header)
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self,"Connection Error","The there was a connection error when connecting to\n{}\nPlease try again once connection is established".format(url))
            return
        print(r.status_code)
        if r.status_code == 200: #This is normal return value
            response_dict = r.json()
            logger.debug(response_dict['message'])
        else: #Something went wrong
            logger.debug(r.text)
            QMessageBox.warning(self,"Connection Error","The there was an error:\n{}".format(r.text))
            return


if __name__.endswith('__main__'):
    app = QApplication(sys.argv)
    execute = CANLogger()
    sys.exit(app.exec_())
    

