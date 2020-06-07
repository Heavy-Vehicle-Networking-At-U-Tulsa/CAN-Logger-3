/*
  Using the SparkFun Cryptographic Co-processor Breakout ATECC508a (Qwiic)
  By: Pete Lewis
  SparkFun Electronics
  Date: August 5th, 2019
  License: This code is public domain but you can buy me a beer if you use this and we meet someday (Beerware license).

  Feel like supporting our work? Please buy a board from SparkFun!
  https://www.sparkfun.com/products/15573

  This example shows how to verify a digital ECC signature of a message using an external public key.
  By "external" public key, we mean that the key lives at the top of this sketch in code, not INSIDE the crypto device.
  Note, this requires that your device be configured with SparkFun Standard Configuration settings.

  ***THIS EXAMPLE WILL FAIL AS IS***
  Every SparkFun Cryptographic Co-processor has a unique private/public keypair.
  You must complete Example_2_Sign. This will print out the public key, message and signature.
  Copy/paste them into the top of this sketch, rename 'publicKey' to 'publicKeyExternal', upload, and verify.

  Try changing a byte (or single bit) in either the message or the signature, and it should fail verification.

  Hardware Connections and initial setup:
  Install artemis in boards manager: http://boardsmanager/All#Sparkfun_artemis
  Plug in your controller board (e.g. Artemis Redboard, Nano, ATP) into your computer with USB cable.
  Connect your Cryptographic Co-processor to your controller board via a qwiic cable.
  Select TOOLS>>BOARD>>"SparkFun Redboard Artemis"
  Select TOOLS>>PORT>> "COM 3" (note, yours may be different)
  Click upload, and follow configuration prompt on serial monitor at 115200.

*/

#include <SparkFun_ATECCX08a_Arduino_Library.h> //Click here to get the library: http://librarymanager/All#SparkFun_ATECCX08a
#include <i2c_t3.h>
#include <sha256.h>

byte hash_message[32];
Sha256* sha256Instance;
ATECCX08A atecc;

// publicKeyExternal, message, and signature come from example 2.
// delete these, and then copy and paste your unique versions here.
// note, you will also need to change the name of the copied array 
// "publicKey[64]" to "publicKeyExternal[64]"

uint8_t publicKeyExternal[64] = {
0xD6,0x78,0xAB,0x2E,0x76,0x16,0xE0,0xF6,0x10,0x47,0x0F,0xB9,0x1C,0x4A,0x1A,0x2D,0xAE,0xB8,0x1C,0x48,0xA2,0x8A,0xAE,0xB8,0x4E,0xC8,0x7B,0x88,0xEB,0xE8,0x50,0xDE,0xCC,0xA2,
0x9B,0x6F,0x53,0x4A,0x21,0x58,0x06,0xF9,0xB8,0x92,0x43,0x01,0x5A,0x5C,0x67,0x18,0xE6,0x51,0x61,0xA0,0xDA,0xBB,0x56,0xCE,0x56,0xFC,0x1B,0xD5,0xCB,0x49
};

uint8_t message[32] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

uint8_t signature[64] = {
0x72,0x1B,0xAA,0xC8,0x15,0x7C,0x68,0x14,0x01,0x3C,0x10,0x84,0x68,
0xF9,0xBA,0xDB,0x9C,0x26,0xAC,0xC0,0x84,0xE7,0xD3,0xEC,0x9B,0x66,
0x32,0x19,0x2C,0xB6,0xEC,0xA6,0xEA,0x24,0xF8,0xC8,0x04,0xD6,0x57,
0x6D,0x3E,0xDF,0xE2,0xF3,0x75,0xE0,0x04,0xD0,0x95,0x72,0x92,0xAA,
0xD0,0x65,0x43,0x1B,0x83,0xDD,0x31,0x35,0xAA,0xAF,0x84,0x00
};


void setup() {
  while(!Serial);
  Wire.begin(I2C_MASTER, 0x00, I2C_PINS_18_19, I2C_PULLUP_EXT, 100000);
  Serial.begin(115200);
  if (atecc.begin() == true)
  {
    Serial.println("Successful wakeUp(). I2C connections are good.");
  }
  else
  {
    Serial.println("Device not found. Check wiring.");
    while (1); // stall out forever
  }

  printInfo(); // see function below for library calls and data handling

  // check for configuration
  if (!(atecc.configLockStatus && atecc.dataOTPLockStatus && atecc.slot0LockStatus))
  {
    Serial.print("Device not configured. Please use the configuration sketch.");
    while (1); // stall out forever.
  }

  printPublicKeyExternal(); // nice debug to ensure you have copied/pasted/renamed properly.
  printMessage(); // nice debug to see what you're verifying. see function below
  printSignature(); // nice debug to see what you're verifying. see function below
  
  sha256Instance = new Sha256();
  sha256Instance->update(message,sizeof(message));
  sha256Instance->final(hash_message);
  // Let's verirfy!
  if (atecc.verifySignature(hash_message, signature, publicKeyExternal)) Serial.println("Success! Signature Verified.");
  else Serial.println("Verification failure.");
}

void loop()
{
  // do nothing.
}

void printPublicKeyExternal()
{
  Serial.println("uint8_t publicKeyExternal[64] = {");
  for (int i = 0; i < sizeof(publicKeyExternal) ; i++)
  {
    Serial.print("0x");
    if ((publicKeyExternal[i] >> 4) == 0) Serial.print("0"); // print preceeding high nibble if it's zero
    Serial.print(publicKeyExternal[i], HEX);
    if (i != 63) Serial.print(", ");
    if ((63 - i) % 16 == 0) Serial.println();
  }
  Serial.println("};");
  Serial.println();
}

void printMessage()
{
  Serial.println("uint8_t message[32] = {");
  for (int i = 0; i < sizeof(message) ; i++)
  {
    Serial.print("0x");
    if ((message[i] >> 4) == 0) Serial.print("0"); // print preceeding high nibble if it's zero
    Serial.print(message[i], HEX);
    if (i != 31) Serial.print(", ");
    if ((31 - i) % 16 == 0) Serial.println();
  }
  Serial.println("};");
  Serial.println();
}

void printSignature()
{
  Serial.println("uint8_t signature[64] = {");
  for (int i = 0; i < sizeof(signature) ; i++)
  {
    Serial.print("0x");
    if ((signature[i] >> 4) == 0) Serial.print("0"); // print preceeding high nibble if it's zero
    Serial.print(signature[i], HEX);
    if (i != 63) Serial.print(", ");
    if ((63 - i) % 16 == 0) Serial.println();
  }
  Serial.println("};");
  Serial.println();
}

void printInfo()
{
  // Read all 128 bytes of Configuration Zone
  // These will be stored in an array within the instance named: atecc.configZone[128]
  atecc.readConfigZone(false); // Debug argument false (OFF)

  // Print useful information from configuration zone data
  Serial.println();

  Serial.print("Serial Number: \t");
  for (int i = 0 ; i < 9 ; i++)
  {
    if ((atecc.serialNumber[i] >> 4) == 0) Serial.print("0"); // print preceeding high nibble if it's zero
    Serial.print(atecc.serialNumber[i], HEX);
  }
  Serial.println();

  Serial.print("Rev Number: \t");
  for (int i = 0 ; i < 4 ; i++)
  {
    if ((atecc.revisionNumber[i] >> 4) == 0) Serial.print("0"); // print preceeding high nibble if it's zero
    Serial.print(atecc.revisionNumber[i], HEX);
  }
  Serial.println();

  Serial.print("Config Zone: \t");
  if (atecc.configLockStatus) Serial.println("Locked");
  else Serial.println("NOT Locked");

  Serial.print("Data/OTP Zone: \t");
  if (atecc.dataOTPLockStatus) Serial.println("Locked");
  else Serial.println("NOT Locked");

  Serial.print("Data Slot 0: \t");
  if (atecc.slot0LockStatus) Serial.println("Locked");
  else Serial.println("NOT Locked");

  Serial.println();

  // Note, omitting printing this devices public key for example 3.
  // This clarifies that we are using an external public key 
  // that is defined at the top of the sketch.
}
