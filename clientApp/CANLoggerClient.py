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

# import boto3
# import botocore
# from botocore.config import Config

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

from ecdsa import VerifyingKey, BadSignatureError, NIST256p
import hashlib

jws = JWS()

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.DEBUG)

AWS_REGION = "us-east-2"
API_ENDPOINT = r"https://47tzdaoo6k.execute-api.us-east-2.amazonaws.com/dev/"
APP_CLIENT_ID = "58tl1drhvqtjkmhs69inh7l1t3"
USER_POOL_ID = "us-east-2_fiNazAdBU"
IDENTITY_TOKEN_NAME = "identity_token.json"
ACCESS_TOKEN_NAME = "access_token.json"

class SerialListener(threading.Thread):
    def __init__(self, rx_queue, serial_port):
        threading.Thread.__init__(self)
        self.rx_queue = rx_queue
        self.ser = serial_port
        self.ser.timeout = None
        self.runSignal = True
        logger.debug("Started Serial Listening Thread on {}".format(self.ser.port))

    def run(self):
        while self.runSignal:
            i = max(1, min(2048, self.ser.in_waiting))
            data = self.ser.read(i)
            self.rx_queue.put(data) 
            # if len(data) > 1:
            #     print(data)
            #     for b in data:
            #         self.rx_queue.put(bytes(b))
            # else:
            #     self.rx_queue.put(data)    

        logger.debug("Serial Listener Thread is finished.")

class CANLogger(QMainWindow):
    def __init__(self):
        super(CANLogger, self).__init__()
        try:
            self.API_KEY = os.environ["CANLogger_API_KEY"]
        except:
            logger.critical(traceback.format_exc())
            QMessageBox.warning(self,"Missing API Key","Please contact Jeremy Daily at Colorado State University to obtain an API key for this application.")
            sys.exit()
        self.statusBar().showMessage("Welcome to the CANLogger App.")

         # Build common menu options
        menubar = self.menuBar()

        #####################
        # FILE
        #####################
        file_menu = menubar.addMenu('&File')
        file_toolbar = self.addToolBar("File")
        
        new_file = QAction(QIcon(r'icons/upload_icon.png'), '&Upload', self)
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

        format_logger = QAction(QIcon(r'icons/format_icon.png'), '&Format SD', self)
        format_logger.setShortcut('Ctrl+F')
        format_logger.setStatusTip('Format the SD Card on the Data Logger')
        format_logger.triggered.connect(self.format_sd_card)
        logger_menu.addAction(format_logger)
        file_toolbar.addAction(format_logger)

        self.setWindowTitle("CAN Logger Client Application")
        
        self.signed_file_metadata = None
        self.access_token         = None
        self.identity_token       = None
        self.refresh_token        = None
        self.connected            = False
        self.encrypted_log_file   = None

        if not self.load_tokens():
            self.login()
        
        initial_message = QLabel("Connect to a CAN Logger to see files (Ctrl+O).")
        self.grid_layout = QGridLayout()
        self.grid_layout.addWidget(initial_message,0,0,1,1)
        main_widget = QWidget()
        main_widget.setLayout(self.grid_layout)
        self.setCentralWidget(main_widget)

        self.show() 

    def format_sd_card(self):
        QMessageBox.confirm(self,"Are you sure?","Formatting will erase all the data on the SD Card. ")
    
    def connect_logger_by_usb(self):
        items =[] 
        for device in serial.tools.list_ports.comports():
            items.append("{} - {}".format(device.device, device.description))
        logger.debug(items)
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
            self.ser = serial.Serial(self.comport)
            self.ser.set_buffer_size(rx_size = 2147483647, tx_size = 2000)
            self.connected = True
            logger.debug("Connected to Serial Port.")
            self.serial_queue = queue.Queue()
            self.serial_thread = SerialListener(self.serial_queue,self.ser)
            self.serial_thread.setDaemon(True) #needed to close the thread when the application closes.
            self.serial_thread.start()
            logger.debug("Started Serial Thread.")

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
    
    def verify_meta_data_text(self,raw_line):
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
                logger.debug("SHA 2-6 Digests in text file doesn't match the calculated value.")
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
    
    def download_file(self):
        row = self.device_file_table.currentRow()
        filename = str(self.device_file_table.item(row, 3).text()) # select the filename entry
        expected_size = int(self.device_file_table.item(row, 8).text()) #
        logger.debug("Downloading file {}".format(filename))
        # empty the queue
        while not self.serial_queue.empty():
            self.serial_queue.get_nowait()
        self.ser.write(b'BIN ' + bytes(filename,'ascii') + b'\n')
        time.sleep(0.020)
        ret_val = b''
        start_time = time.time()
        timeout = 20
        try:
            while len(ret_val) < expected_size:
                try:
                    character = self.serial_queue.get()
                    ret_val += character
                    #print(character)
                except:
                    traceback.format_exc()
                current_time = (time.time() - start_time)
                if  current_time > timeout:
                    logger.debug("Download timed out.")
                    break
        except: 
            logger.debug(traceback.format_exc())
        downloaded_size = len(ret_val)
        logger.debug("Downloaded {} bytes of {}".format(downloaded_size,expected_size))
        okPressed = QMessageBox.question(self,"Downloaded Bytes","Do you want to save the following {} bytes?\n{}\n...\n{}".format(downloaded_size,ret_val[:50],ret_val[-50:]))
        self.encrypted_log_file = ret_val

    def list_device_files(self):
        while not self.connected:
            if self.connect_logger_by_usb() is None:
                return
        # empty the queue
        while not self.serial_queue.empty():
            self.serial_queue.get_nowait()
        time.sleep(0.1)
        self.ser.write(b'LS A\n')
        time.sleep(0.1)
        file_meta_data_list=[]
        file_raw_meta_data_list=[]
        
        ret_val = b''
        while not self.serial_queue.empty():
            character = self.serial_queue.get()
            ret_val += character
        
        response=ret_val.split(b'\r\n')
        logger.debug(response)
        
        for line in response:
            try:
                logger.debug(line)
                line_data = line.strip().split()
                latest_file_name = str(line_data[3],'ascii')
                latest_file_size = int(line_data[2])
                if latest_file_name[-3:] == 'txt' and latest_file_size > 500:
                    file_meta_data_list.append(line_data)
            except IndexError:
                logger.debug(traceback.format_exc())

        header_labels = ["Date & Time",
                         "CAN0 Bitrate",
                         "CAN1 Bitrate",
                         "Filename",
                         "Logger Serial Number",
                         "Initialization Vector",
                         "Encrypted Session Key",
                         "Device Public Key",
                         "Size",
                         "Binary File SHA-256 Hash Digest",
                         "Text File SHA-256 Hash Digest",
                         "Digital Signature of Text SHA Digest",
                         "Verification"]
        NUM_COLS = len(header_labels)
        NUM_ROWS = len(file_meta_data_list)
        self.device_file_table = QTableWidget(NUM_ROWS,NUM_COLS,self)
        self.device_file_table.setHorizontalHeaderLabels(header_labels)
        self.device_file_table.setSelectionBehavior(QTableView.SelectRows);
        self.device_file_table.doubleClicked.connect(self.download_file)
        self.device_file_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.grid_layout.addWidget(self.device_file_table ,0,0,1,1)
        row = 0
        for line_data in file_meta_data_list:
            latest_file_name = str(line_data[3],'ascii')
            latest_file_size = int(line_data[2])
            # empty the queue
            time.sleep(.1)
            while not self.serial_queue.empty():
                self.serial_queue.get_nowait()
            logger.debug("Downloading {} bytes from {}".format(latest_file_size,latest_file_name))    
            #send the command to the Logger to download data
            self.ser.write(b'BIN ' + bytes(latest_file_name[:-3]+"txt",'ascii') + b'\n') 
            time.sleep(0.1);
            ret_val=b''
            while not self.serial_queue.empty():
                character = self.serial_queue.get()
                ret_val += character    
            bytes_in_file = ret_val[:latest_file_size]
            if self.verify_meta_data_text(bytes_in_file):
                self.meta_data = bytes_in_file.decode('ascii').split(",")
                self.meta_data.append("Verified")
                logger.debug("file meta_data has {} elements:".format(len(self.meta_data))) 
                logger.debug("{}".format(self.meta_data))
                # Insert the time first, because it has a bunch of colons 
                col = 0
                self.device_file_table.setItem(row,col,QTableWidgetItem(self.meta_data[0]))
                col += 1
                for entry in self.meta_data[col:]:
                    try:
                        d = entry.split(":")[1] #Try to take the value (i.e. everything after the colon) as opposed to the label
                    except IndexError:
                        d = entry #There was no colon, so 
                    self.device_file_table.setItem(row,col,QTableWidgetItem(d))
                    col+=1
                row+=1

            else:
                self.device_file_table.removeRow(row)
                logger.debug("Removing row {}".format(row))
                continue    
        self.device_file_table.resizeColumnsToContents()
        return
         

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
        try:
            with open('username.txt','r') as f:
                stored_user = f.read()
            username_saved = True
        except:
            stored_user = ''
            username_saved = False
        self.user, okPressed = QInputDialog.getText(self, "Username","Username (e-mail):", QLineEdit.Normal, stored_user)
        
        # validate input
        if not okPressed:
            return
        if self.user == '':
            return
        
        if stored_user == self.user:
            username_saved == True
        else:
            username_saved == False

        try:
            with open('password.txt','r') as f:
                stored_password = f.read()
            pass_word_saved = True
        except:
            stored_password = ''
            pass_word_saved = False
        password, okPressed = QInputDialog.getText(self, "Password","Input password for \n{}".format(self.user), QLineEdit.Password, stored_password)
        
        # Validate Input
        if not okPressed:
            return
        if password == '':
            return
        
        if stored_password == password:
            pass_word_saved == True
        else:
            pass_word_saved == False

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
            with open(ACCESS_TOKEN_NAME,'w') as fp:
                json.dump(self.access_token,fp)
            self.identity_token = response_data["AuthenticationResult"]["IdToken"]
            with open(IDENTITY_TOKEN_NAME,'w') as fp:
                json.dump(self.identity_token,fp)
            self.refresh_token = response_data["AuthenticationResult"]["RefreshToken"]
            self.load_tokens()
            self.decode_jwt()
            if not pass_word_saved:
                _password, okPressed = QInputDialog.getText(self, "Save Password","DANGER: Do you want to save your clear text username and password for \n{}? Press OK to save.".format(self.user), QLineEdit.Password, password)
                if okPressed:
                    with open('password.txt','w') as f:
                        f.write(password)
                    with open('username.txt','w') as f:
                        f.write(self.user) 
        elif r.status_code == 400: #Incorrect username or password
            message = r.json()["message"]
            logger.warning(message)
            QMessageBox.warning(self,"Incorrect Username or Password",message)
            self.login()
        else: #Something went wrong
            logger.warning("There was an issue with the web response.")
            logger.debug(r.text)
            

    def load_tokens(self):
        try:
            with open(IDENTITY_TOKEN_NAME,'r') as fp:
                self.identity_token = json.load(fp)
            with open(ACCESS_TOKEN_NAME,'r') as fp2:
                self.access_token = json.load(fp2)
            return self.decode_jwt(display = True)
        except:
            logger.debug(traceback.format_exc())
            self.access_token = None
            self.identity_token = None
            return False

    def decode_jwt(self,display=False):
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
            if display:
                message = 'Congratulations, the following token has been verified.\nID Token:\n'
                for k,v, in plain_text_dict.items():
                    message += "{}: {}\n".format(k,v)
                logger.debug(message)
                QMessageBox.information(self,"ID Token",message)
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
    

