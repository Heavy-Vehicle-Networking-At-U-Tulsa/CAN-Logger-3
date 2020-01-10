/*
 * NMFTA CAN Logger 3 Project   
 * 
 * Arduino Sketch for provisioning CAN Logger 3 by sending the device serial number and
 * exchanging public keys along with their signatures with the Amazon Web Services server
 * 
 * Written By Duy Van
 * Colorado State University
 * Department of Systems Engineering
 * 
 * 7 Janurary 2019
 * 
 * Released under the MIT License
 *
 * Copyright (c) 2019        Jeremy S. Daily, Duy Van
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * 
 */

#include <SparkFun_ATECCX08a_Arduino_Library.h> //Click here to get the library: http://librarymanager/All#SparkFun_ATECCX08a
#include <i2c_t3.h> //use to communicate with the ATECC608a cryptographic coprocessor
#include <sha256.h> //Hash device public key 

ATECCX08A atecc;

#define SHA256_BLOCK_SIZE 32          // SHA256 outputs a 32 byte digest
Sha256* sha256Instance;
byte hash[SHA256_BLOCK_SIZE];

byte message[64];
uint8_t server_public_key[64];

String serial_string;

void setup() {
  // put your setup code here, to run once:


  
  //Initiate ATECC608A connection
  Wire.begin(I2C_MASTER, 0x00, I2C_PINS_18_19, I2C_PULLUP_EXT, 100000);
  if (atecc.begin() == true)
  {
    Serial.println("Successful wakeUp(). I2C connections are good.");
  }
  else
  {
    Serial.println("Device not found. Check wiring.");
    while (1); // stall out forever
  }

  
  
}

void send_data(){
  //Write and Lock Configuration made specifically for the CAN Logger 3 application, please see library for more detail
  /*
  Serial.print("Write Config: \t");
  if (atecc.writeProvisionConfig() == true) Serial.println("Success!");
  else Serial.println("Failure or Config has already been locked.");

  Serial.print("Lock Config: \t");
  if (atecc.lockConfig() == true) Serial.println("Success!");
  else Serial.println("Failure or Config has already been locked.");
  
  //Create device ECC private key and lock it on data slot 0
  Serial.print("Key Creation: \t");
  if (atecc.createNewKeyPair() == true) Serial.println("Success!");
  else Serial.println("Failure or Data Slot has already been locked.");

  Serial.print("Lock Private Key Data Slot: \t");
  if (atecc.lockDataSlot(0) == true) Serial.println("Success!");
  else Serial.println("Failure or Data Slot has already been locked.");
  */

  atecc.writeProvisionConfig();
  atecc.lockConfig();
  atecc.createNewKeyPair();
  atecc.lockDataSlot(0);
  atecc.readConfigZone(false); // produces a serial number
  atecc.generatePublicKey(0,false); //compute public key from slot 0 private key
  //Do we need to sign the public key since the we trust the connection and we don't have a hardcoded key on either side yet?
  //sha256Instance = new Sha256();
  //sha256Instance->update(atecc.publicKey64Bytes, 64);
  //sha256Instance->final(hash);
  //delete sha256Instance;
  //atecc.createSignature(hash,0,false);
  
  //Need to send atecc.publicKey64Bytes, atecc.serialNumber, (and atecc.signature?) to the server through python
  //Send serial number to python through local serial
  for (int n = 0; n < sizeof(atecc.serialNumber);n++){
    char hex_digit[3];
    sprintf(hex_digit,"%02X",atecc.serialNumber[n]);
    Serial.write(hex_digit);
  }
  Serial.write('\n');
  //Send device public key to python through local serial
  for (int n = 0; n < sizeof(atecc.publicKey64Bytes);n++){
    char hex_digit[3];
    sprintf(hex_digit,"%02X",atecc.publicKey64Bytes[n]);
    Serial.write(hex_digit);
  }
}

void loop() {
  // put your main code here, to run repeatedly:
  //Wait for Python to initiate the provision process with the string "KEY"
  while(Serial.available() == 0);//wait for Python input
  serial_string = Serial.readStringUntil('\n');
  if (serial_string.equalsIgnoreCase("KEY")) 
  {
    send_data();
    
    //Wait for server to send its public key
    while (Serial.available() == 0);//wait for Python input again
    
    for (int i = 0; i < 64; i++){
      byte c = Serial.read();
      server_public_key[i] = c;
      
      char hex_digit[3];
      sprintf(hex_digit,"%02X", server_public_key[i]);
      Serial.print(hex_digit);
    }
    
    atecc.loadPublicKey(server_public_key,true); //Load the received public key to slot 10 on the ATECC
    atecc.lockDataAndOTP(); //Lock Data and OTP zone in order to read the server public key later for ECDH
    
  }
  else {};
}
