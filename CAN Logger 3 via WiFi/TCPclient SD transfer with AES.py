#!/usr/bin/python3
import socket
import sys
import uuid
import struct
from Crypto.Cipher import AES

key_byte = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]

key_convert = ("".join(["{:02X}".format(b) for b in key_byte]))
key_string=(bytes.fromhex(key_convert))
decipher = AES.new(key_string,AES.MODE_ECB)

'''For testing decryption
text_byte = [0xDE, 0x4B, 0xE8, 0x89, 0x3B, 0xA1, 0xC9, 0xD5,
                    0x82, 0x81, 0x9F, 0xDB, 0x7A, 0x89, 0x30, 0xDA]

text_convert = ("".join(["{:02X}".format(b) for b in text_byte]))
text_string=(bytes.fromhex(text_convert))

print(decipher.decrypt(text_string))
'''

LOG_FILE_NAME = 'logfile_{}.bin'.format(uuid.uuid4()) #uuid4 generates a random universally unique identifier
Buffer_size = 16


#setup tcp client for CAN data transfer
SERVER_IP = "192.168.1.1" #insert IP address of server here
SERVER_PORT = 80

print("Connect to {} Port {}.".format(SERVER_IP, SERVER_PORT))
print('---------------------------------------------------------------------')

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.connect((SERVER_IP, SERVER_PORT))
except OSError:
    print("Could not connect TCP Socket. Make sure SERVER_IP is correct.")
    sys.exit()


message_list = []


with open (LOG_FILE_NAME, 'wb') as file:
    while True:
        data = sock.recv(Buffer_size)
        if not data: break;
        #print(data)
        print(decipher.decrypt(data))
        #file.write(data)
        file.write(data)
    file.close()        
sock.close()
sys.exit()