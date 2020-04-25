from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils

#print("ECDH----------------------------------------------------------------------------------")
#print("--------------------------------------------------------------------------------------")
#generate server ECC key pair
server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
server_public_key = (server_private_key.public_key())

#Serializing the server public key
serialized_public = server_public_key.public_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PublicFormat.SubjectPublicKeyInfo)


public_key_hex = ((base64.b64decode(serialized_public.splitlines()[1]).hex()) + \
					(base64.b64decode(serialized_public.splitlines()[2]).hex()))[54:]

public_key_1 = public_key_hex[0:64]
public_key_2 = public_key_hex[64:128]
#print(public_key_hex)
#print(public_key_1)
#print(public_key_2)
public_key_list = []
for k in range(64):
	public_key_list.append('0X'+public_key_hex[2*k]+public_key_hex[2*k+1])

print("Server public Key is:",",".join(public_key_list),'\n')


PEM_public_key_first = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE'
PEM_public_key_last = '\n-----END PUBLIC KEY-----\n'
#Input Teensy public key manually here:
Teeny_public_key_hex = [0X0D,0XD3,0XF9,0X43,0X97,0X0E,0X03,0XE9,0X88,0X1D,0XF7,0X6E,0X57,0X25,0X6F,0XD1,
0XFB,0X57,0X31,0XD8,0X1B,0X4E,0X34,0X2E,0X93,0X80,0X82,0X9C,0X88,0X9F,0X8D,0X89,
0X78,0X64,0XFA,0XB0,0X66,0X9E,0X7E,0X6D,0XA5,0X1C,0XEE,0X90,0X6E,0XA8,0X37,0X27,
0X9F,0XB0,0XBA,0XAF,0X3B,0XC8,0XCC,0XCB,0XA7,0X20,0XFA,0X58,0X6E,0XFD,0X9F,0X24
]

#Convert Teensy public key to base64 format
Teensy_PEM_public_key = base64.b64encode(bytes(Teeny_public_key_hex)).decode('ascii')

#Finalize the teensy public key in serilized PEM format
public_key_teensy_string = PEM_public_key_first + Teensy_PEM_public_key[:28]+'\n'+ Teensy_PEM_public_key[28:] + PEM_public_key_last
serialized_public_teensy = bytes(public_key_teensy_string,'ascii')

#Print Teensy public key
public_key_hex_teensy = ((base64.b64decode(serialized_public_teensy.splitlines()[1]).hex()) + \
					(base64.b64decode(serialized_public_teensy.splitlines()[2]).hex()))[54:]
print("Teensy Public Key:",public_key_hex_teensy,"\nLength:", int(len(public_key_hex_teensy)/2),'\n')

#Load teensy public key
teensy_public_key = serialization.load_pem_public_key(serialized_public_teensy,backend=default_backend())

#Derive shared secret
shared_secret = server_private_key.exchange(ec.ECDH(),teensy_public_key)
print("Shared secret:",shared_secret.hex())



'''
print("")
print("Signing Data--------------------------------------------------------------------------")
print("--------------------------------------------------------------------------------------")
#data to be signed
data_hex = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]
data = bytes(data_hex)

print("Message:",data.hex().upper())

signature1 = server_private_key.sign(data,ec.ECDSA(hashes.SHA256()))
signature1_hex = utils.decode_dss_signature(signature1)
#print(hex(signature1_hex[0]))
#print(hex(signature1_hex[1]))
string1 = hex(signature1_hex[0])[2:]
string2 = hex(signature1_hex[1])[2:]
int_list1=[]
int_list2=[]
for i in range(0,len(string2),2):
	int_list1.append(int(string1[i:i+2],16))
	int_list2.append(int(string2[i:i+2],16))
#print(int_list1)
#print(int_list1)
pretty_print_1 = ", ".join(["0x{:02X}".format(b) for b in int_list1])
pretty_print_2 = ", ".join(["0x{:02X}".format(b) for b in int_list2])
print("First 32 Bytes of Signature: ",pretty_print_1)
print()
print("Second 32 Bytes of Signature: ",pretty_print_2)
'''