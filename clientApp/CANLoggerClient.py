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
import os

sys.path.insert(1, '../serverless')
from utils import verify_meta_data_text, decode_jwt

import serial
import serial.tools.list_ports

from ecdsa import VerifyingKey, BadSignatureError, NIST256p
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
        self.home_directory = os.getcwd()
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

        provision_logger = QAction(QIcon(r'icons/provision_icon.png'), '&Provision', self)
        provision_logger.setShortcut('Ctrl+P')
        provision_logger.setStatusTip('Register important data with the server.')
        provision_logger.triggered.connect(self.provision)
        logger_menu.addAction(provision_logger)
        file_toolbar.addAction(provision_logger)

        get_key = QAction(QIcon(r'icons/get_key.png'), 'Get &Key', self)
        get_key.setShortcut('Ctrl+K')
        get_key.setStatusTip('Decrypt a session key.')
        get_key.triggered.connect(self.get_session_key)
        logger_menu.addAction(get_key)
        file_toolbar.addAction(get_key)

        get_password = QAction(QIcon(r'icons/get_password.png'), 'Get &Password', self)
        get_password.setShortcut('Ctrl+I')
        get_password.setStatusTip('Decrypt the server private key password for the current device.')
        get_password.triggered.connect(self.decrypt_password)
        logger_menu.addAction(get_password)
        file_toolbar.addAction(get_password)

        self.setWindowTitle("CAN Logger Client Application")
        
        self.meta_data_dict       = None
        self.access_token         = None
        self.identity_token       = None
        self.refresh_token        = None
        self.connected            = False
        self.encrypted_log_file   = None
        self.session_key          = None
        self.encrypted_log_file   = None


        initial_message = QLabel("Connect to a CAN Logger to see files (Ctrl+O).")
        self.grid_layout = QGridLayout()
        self.grid_layout.addWidget(initial_message,0,0,1,1)
        main_widget = QWidget()
        main_widget.setLayout(self.grid_layout)
        self.setCentralWidget(main_widget)

        self.show() 
        if not self.load_tokens():
            self.login()
    
    def provision(self):
        url = API_ENDPOINT + "provision"
        header = {}
        header["x-api-key"] = self.API_KEY #without this header, the API Gateway will return a 403: Forbidden message.
        header["Authorization"] = self.identity_token #without this header, the API Gateway will return a 401: Unauthorized message

        while not self.connected:
            if self.connect_logger_by_usb() is None:
                return
        # empty the queue
        while not self.serial_queue.empty():
            self.serial_queue.get_nowait()
        time.sleep(0.5)
        self.ser.write(b'KEY\n')
        time.sleep(0.5)
        
        ret_val = b''
        while not self.serial_queue.empty():
            character = self.serial_queue.get()
            ret_val += character
        
        response=ret_val.split(b'\n')
        logger.debug(response)

        serial_number = response[0]
        device_public_key = response[1]

        
        try:
            data = {'serial_number': base64.b64encode(serial_number).decode("ascii"),
                    'device_public_key': base64.b64encode(device_public_key).decode("ascii"),
                   }
        except TypeError:
            logger.warning("Must have data to get key.")
            return

        try:
            r = requests.post(url, json=data, headers=header)
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self,"Connection Error","The there was a connection error when connecting to\n{}\nPlease try again once connection is established".format(url))
            return
        print(r.status_code)
        print(r.text)
        if r.status_code == 200: #This is normal return value
            data_dict = r.json()
            server_public_key=base64.b64decode(data_dict["server_public_key"]).hex().upper()
            server_pem_key_pass=base64.b64decode(data_dict["server_pem_key_pass"]).decode('ascii')
            encrypted_rand_pass=data_dict["encrypted_rand_pass"] #base64 format in string type
            self.server_pem = server_pem_key_pass
            self.rand_pass = encrypted_rand_pass
            self.serial_id = serial_number.decode('ascii')


            assert len(server_public_key)==128
            print("uint8_t server_public_key[64] = {")
            for i in range(0,len(server_public_key),2):
                print("0x{}{},".format(server_public_key[i],server_public_key[i+1]),end='')
            print("};")

            # Visual key hash confirmation before sending the server public key to the device
            device_pub_key_bytes = bytearray.fromhex(device_public_key.decode("ascii"))
            server_public_key_bytes = base64.b64decode(data_dict["server_public_key"])   
            device_public_key_hash = hashlib.sha256(device_pub_key_bytes).digest().hex().upper()
            server_public_key_hash = hashlib.sha256(server_public_key_bytes).digest().hex().upper()
            
            #Key Comparision 
            buttonReply = QMessageBox.question(self, 'Do the keys match?', "Device Serial Number: {}\nDevice public key provisioning hash: {}\nServer public key provisioning hash: {}".format(serial_number.decode('ascii'),device_public_key_hash[:10],server_public_key_hash[:10]), QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if buttonReply == QMessageBox.Yes:
                self.ser.write(bytearray.fromhex(server_public_key))
                time.sleep(1)
                ret_val = b''
                while not self.serial_queue.empty():
                    character = self.serial_queue.get()
                    ret_val += character
                if ret_val == bytes(server_public_key,'ascii'):
                    QMessageBox.information(self,"Provisioning Process","Server Public Key has been stored and locked in device {}".format(self.serial_id))
                    
                else:
                    QMessageBox.warning(self,"Error","Key is already locked!")

            else:
                QMessageBox.warning(self,"Error","Keys do not match!")

            self.ask_to_save() #Will be moved under Success

    #Ask the operator if they want to save the server_pem_key and encrypted_rand_pass
    def ask_to_save(self):
        buttonReply = QMessageBox.question(self, 'Save File', "Would you like to save the server private key and its encrypted password?", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if buttonReply == QMessageBox.Yes:
            self.save_security_list()


    def save_security_list(self):
        #Save the server pem key with pass and encrypted password to a text file
        options = QFileDialog.Options()
        options |= QFileDialog.Detail
        self.data_file_name, data_file_type = QFileDialog.getSaveFileName(self,
                                            "Save File",
                                            self.home_directory + "/" + "CAN Logger 3 Security List",
                                            "JSON Files (*.json);;All Files (*)",
                                            options = options)
        if self.data_file_name:
            if os.path.exists(self.data_file_name) == True:
            #if os.path.getsize(self.data_file_name) >0:
                with open(self.data_file_name,'r') as file:
                    data = json.load(file)
                data[self.serial_id] = {'sever_pem_key':self.server_pem,'encrypted_password':self.rand_pass}
                with open(self.data_file_name,'w') as file:
                    json.dump(data,file, indent=4)
                
            else:
                with open(self.data_file_name,'w') as file:
                    data = {self.serial_id:{'sever_pem_key':self.server_pem,'encrypted_password':self.rand_pass}}
                    json.dump(data,file, indent=4)
            QMessageBox.information(self,"Save File","File is successfully saved!")
                

    #Send the encrypted server pem key password to the device for encryption
    #Must be done after the provisioning process
    def decrypt_password(self):
        QMessageBox.information(self,"Deccrypt Encrypted Password","Please choose the security list JSON file from Provisioning step.")
        options = QFileDialog.Options()
        options |= QFileDialog.Detail
        self.data_file_name, data_file_type = QFileDialog.getOpenFileName(self,
                                            "Open JSON File",
                                            self.home_directory,
                                            "JSON Files (*.json);;All Files (*)",
                                            options = options)

        if self.data_file_name:
            with open(self.data_file_name,'r') as file:
                data = json.load(file)

            #Open serial COM port if not connected
            while not self.connected:
                if self.connect_logger_by_usb() is None:
                    return
            # empty the queue
            while not self.serial_queue.empty():
                self.serial_queue.get_nowait()
            time.sleep(0.5)
            self.ser.write(b'PASSWORD\n')
            time.sleep(0.5)
            
            ret_val = b''
            while not self.serial_queue.empty():
                character = self.serial_queue.get()
                ret_val += character
            response = ret_val.split(b'\n')
            serial_number =response[0].decode('ascii')
            encrypted_pass = base64.b64decode(bytes(data[serial_number]["encrypted_password"],'ascii'))
            print(encrypted_pass)
            self.ser.write(encrypted_pass)
            time.sleep(1)

            ret_val = b''
            while not self.serial_queue.empty():
                character = self.serial_queue.get()
                ret_val += character
            typable_pass = bytes.fromhex(ret_val.decode('ascii'))

            #Display the decrypted password
            msg=QMessageBox()
            msg.setIcon(QMessageBox.Information)
            msg.setText("The plain text password is:\n{}".format(typable_pass))
            msg.setWindowTitle("Decrypt Password")
            msg.setTextInteractionFlags(Qt.TextSelectableByMouse)
            msg.exec_()







    def get_session_key(self):
        url = API_ENDPOINT + "auth"
        header = {}
        header["x-api-key"] = self.API_KEY #without this header, the API Gateway will return a 403: Forbidden message.
        header["Authorization"] = self.identity_token #without this header, the API Gateway will return a 401: Unauthorized message
        try:
            data = {'serial_number': self.meta_data_dict["serial_num"],
                'file_uid': self.meta_data_dict['file_uid'],
                'session_key': self.meta_data_dict["session_key"],
                'digest': base64.b64decode(self.meta_data_dict["binary_sha_digest"]).hex().upper()
               }
            logger.debug(data)
        except TypeError:
            logger.warning("Must have data to get key.")
            return
        except KeyError:
            logger.warning("Must upload file first.")
            return
        try:
            r = requests.post(url, json=data, headers=header)
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self,"Connection Error","The there was a connection error when connecting to\n{}\nPlease try again once connection is established".format(url))
            return
        print(r.status_code)
        print(r.text)
        if r.status_code == 200: #This is normal return value
            self.session_key = base64.b64decode(r.text)
            print("session_key = {}".format(self.session_key))
            QMessageBox.information(self,"Session Key","The Session Key was recovered from the secure server.")
            self.download_file()
            self.decrypt_file()
        else:
            QMessageBox.information(self,"Server Return","The server returned a status code {}.\n{}".format(r.status_code,r.text))  

    def format_sd_card(self):
        QMessageBox.question(self,"Are you sure?","Formatting will erase all the data on the SD Card. ")
    
    def decrypt_file(self):
        if self.session_key is None:
            logger.debug("Decryption Needs a Session Key")
        # Calculate SHA of data
        # compare SHA If SHA is the same, Proceed
        #logger.debug(self.meta_data_dict["init_vect"])
        iv = base64.b64decode(self.meta_data_dict["init_vect"])
        #Change this. The key is hard coded for testing
        #self.session_key = bytearray.fromhex('CB3944D1881FB2A0AFF350D51FB0D802')
        cipher = Cipher(algorithms.AES(self.session_key), 
                        modes.CBC(iv), 
                        backend=default_backend())
        decryptor = cipher.decryptor()
        self.decrypted_log = decryptor.update(self.encrypted_log_file) + decryptor.finalize()
        logger.debug("Decrypted Log: {}".format(self.decrypted_log[:1024]))
        logger.debug(len(self.decrypted_log))


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
        self.encrypted_log_file = ret_val
        
        downloaded_bin_hash = hashlib.sha256(self.encrypted_log_file).digest()
        logger.debug("Calculated Hash:\n{}".format(downloaded_bin_hash))

        stored_hash = base64.b64decode(self.meta_data_dict["binary_sha_digest"])
        logger.debug("Stored Hash:\n{}".format(stored_hash))

        if downloaded_bin_hash == stored_hash:
            logger.debug("SHA-256 digests match. Log File is authenticate.")
        else:
            logger.debug("Mismatch of SHA-256 digests. Log File is not authenticated.")

        
    
    def load_meta_data(self):
        self.meta_data_dict = {}
        row = self.device_file_table.currentRow()
        self.meta_data_dict["datetime"] = str(self.device_file_table.item(row, 0).text()) #
        self.meta_data_dict["CAN0"] = int(self.device_file_table.item(row, 1).text()) # select the filename entry
        self.meta_data_dict["CAN1"] = int(self.device_file_table.item(row, 2).text()) # select the filename entry
        self.meta_data_dict["filename"] = str(self.device_file_table.item(row, 3).text()) #
        self.meta_data_dict["serial_num"] = str(self.device_file_table.item(row, 4).text()) #
        self.meta_data_dict["init_vect"] = base64.b64encode(bytearray.fromhex(str(self.device_file_table.item(row, 5).text()))).decode('ascii') #string of base64 encoded bytes
        self.meta_data_dict["session_key"] = base64.b64encode(bytearray.fromhex(str(self.device_file_table.item(row, 6).text()))).decode('ascii') #string of base64 encoded bytes
        self.meta_data_dict["device_public_key"] = base64.b64encode(bytearray.fromhex(str(self.device_file_table.item(row, 7).text()))).decode('ascii') #string of base64 encoded bytes
        self.meta_data_dict["filesize"] = int(self.device_file_table.item(row, 8).text()) #
        self.meta_data_dict["binary_sha_digest"] = base64.b64encode(bytearray.fromhex(str(self.device_file_table.item(row, 9).text()))).decode('ascii') #string of base64 encoded bytes
        self.meta_data_dict["text_sha_digest"] = base64.b64encode(bytearray.fromhex(str(self.device_file_table.item(row, 10).text()))).decode('ascii') #string of base64 encoded bytes
        self.meta_data_dict["signature"] = base64.b64encode(bytearray.fromhex(str(self.device_file_table.item(row, 11).text()))).decode('ascii') #string of base64 encoded bytes
        self.meta_data_dict["base64"] = str(self.device_file_table.item(row, 13).text())
        for k,v in self.meta_data_dict.items():
            logger.debug("{}: {}".format(k,v))

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
                         "Verification",
                         "Base64 encoded meta data"]
        NUM_COLS = len(header_labels)
        NUM_ROWS = len(file_meta_data_list)
        self.device_file_table = QTableWidget(NUM_ROWS,NUM_COLS,self)
        self.device_file_table.setHorizontalHeaderLabels(header_labels)
        self.device_file_table.setSelectionBehavior(QTableView.SelectRows);
        self.device_file_table.doubleClicked.connect(self.download_file)
        self.device_file_table.itemSelectionChanged.connect(self.load_meta_data)
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
            if verify_meta_data_text(bytes_in_file):
                self.meta_data = bytes_in_file.decode('ascii').split(",")
                self.meta_data.append("Verified")
                self.meta_data.append(base64.b64encode(bytes_in_file).decode('ascii'))
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
            password_saved = True
        except:
            stored_password = ''
            password_saved = False
        password, okPressed = QInputDialog.getText(self, "Password","Input password for \n{}".format(self.user), QLineEdit.Password, stored_password)
        
        # Validate Input
        if not okPressed:
            return
        if password == '':
            return
        
        if stored_password == password:
            password_saved == True
        else:
            password_saved == False

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

            if not (password_saved and username_saved):
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
            user_token = decode_jwt(self.identity_token)
            for k,v in user_token.items():
                logger.debug("{}: {}".format(k,v))
            return 
        except:
            logger.debug(traceback.format_exc())
            self.access_token = None
            self.identity_token = None
            return False

   

    def upload_file(self):
        if self.meta_data_dict is None:
            QMessageBox.warning(self,"Select File","Please connect a device and select a file.")
            return

        if not decode_jwt(self.identity_token):
            message = "A valid webtoken is not available to upload."
            logger.warning(message)
            QMessageBox.warning(self,"Invalid Token",message)
            return

        url = API_ENDPOINT + "upload"
        header = {}
        header["x-api-key"] = self.API_KEY #without this header, the API Gateway will return a 403: Forbidden message.
        header["Authorization"] = self.identity_token #without this header, the API Gateway will return a 401: Unauthorized message
        logger.debug("Using the following header:\n{}".format(header))
        try:
            r = requests.post(url, data=self.meta_data_dict["base64"], headers=header)
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self,"Connection Error","The there was a connection error when connecting to\n{}\nPlease try again once connection is established".format(url))
            return
        print(r.status_code)
        if r.status_code == 200: #This is normal return value
            response_dict = r.json()
            logger.debug(response_dict['upload_link'])
            if self.encrypted_log_file is None:
                self.download_file()

            r1 = requests.post( response_dict['upload_link']['url'], 
                                data=response_dict['upload_link']['fields'], 
                                files={'file': self.encrypted_log_file}
                               )
            logger.debug(r1.status_code)
            logger.debug(r1.text)
            if r1.status_code == 204:
                self.meta_data_dict['file_uid']=response_dict['upload_link']['fields']['key']
                QMessageBox.information(self,"Success", "Successfully uploaded binary file.\nKey: {}".format(self.meta_data_dict['file_uid']))
                                
        else: #Something went wrong
            logger.debug(r.text)
            QMessageBox.warning(self,"Connection Error","The there was an error:\n{}".format(r.text))
            return


if __name__.endswith('__main__'):
    app = QApplication(sys.argv)
    execute = CANLogger()
    sys.exit(app.exec_())
    

