#include <SparkFun_ATECCX08a_Arduino_Library.h> 
#include <i2c_t3.h>

ATECCX08A atecc;


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

  Serial.println("Would you like to configure your Cryptographic Co-processor ? (y/n)");
  Serial.println("***Note, this is PERMANENT and cannot be changed later***");
  Serial.println("***If you do not want to do this, type an 'n' or unplug now.***");

  while (Serial.available() == 0); // wait for user input

  if (Serial.read() == 'y')
  {
    Serial.println();
    Serial.println("Configuration beginning.");

    Serial.print("Write Config: \t");
    if (atecc.writeProvisionConfig() == true) Serial.println("Success!");
    else Serial.println("Failure.");

    Serial.print("Lock Config: \t");
    if (atecc.lockConfig() == true) Serial.println("Success!");
    else Serial.println("Failure.");

    Serial.print("Key Creation: \t");
    if (atecc.createNewKeyPair() == true) Serial.println("Success!");
    else Serial.println("Failure.");

    Serial.println("Configuration done.");
    Serial.println();
    
    //Lock data slot 0
    atecc.lockDataSlot(0);
    //Print ATECC public key
    atecc.generatePublicKey(0,false); //compute public key from slot 0 private key
    Serial.print("ATECC Public Key: \n");
    for (int n = 0; n < sizeof(atecc.publicKey64Bytes);n++){
    char hex_digit[3];
    sprintf(hex_digit,"%02X",atecc.publicKey64Bytes[n]);
    Serial.print("0X");
    Serial.print(hex_digit);
    Serial.print(",");
    if ((n+1)%16==0) Serial.println();//New line every 16 bytes
    }
    //load_public_key();
    //lock_data();
  }
  else
  {
    Serial.println("Unfortunately, you cannot use any features of the ATECCX08A without configuration and locking.");
  }

  printInfo(); // Print info again to see lock statuses. And if all is good, print the generated public key!
}

void loop()
{
  // do nothing.
}
void load_public_key(){
  Serial.println("Load server public key");
    //Random 64-byte server public key
    uint8_t server_public_key[64] = {0X44,0X45,0X7d,0X9e,0Xa5,0X49,0X19,0Xd4,0X48,0X56,0X3a,0X75,0X3c,0X61,0Xac,
                              0Xc9,0X08,0X14,0X91,0X62,0Xc0,0Xe1,0Xe4,0Xaf,0X15,0Xdb,0Xca,0X04,0X92,0X9f,
                              0X71,0X51,0X20,0X1b,0Xb8,0Xe3,0X29,0Xe1,0X16,0Xd2,0X68,0Xf4,0X93,0X11,0Xac,
                              0X8f,0Xd2,0X64,0X11,0X24,0X93,0Xba,0Xa1,0X48,0X1d,0Xd9,0X87,0X39,0X8b,0Xc7,
                              0Xaf,0Xf7,0X49,0X8a};
    Serial.print("Load Public Key: \t");
    if (atecc.loadPublicKey(server_public_key,false) == true) Serial.println("Success!");
    else Serial.println("Failure.");

    //Print loaded server public key
  atecc.readPublicKey(false);//Read the stored server public key
  Serial.print("Server Public Key: \n");
  for (int j =0;j<sizeof(atecc.storedPublicKey);j++){
    char hex_digit[3];
    sprintf(hex_digit,"%02X", atecc.storedPublicKey[j]);
    Serial.print(hex_digit);
    }
  Serial.println();
}

void lock_data(){
  Serial.print("Lock data and OTP zone: \t");
    if (atecc.lockDataAndOTP() == true) Serial.println("Success!");
    else {
      Serial.println("Failed!");
    }
}

void printInfo()
{
  
  // Read all 128 bytes of Configuration Zone
  // These will be stored in an array within the instance named: atecc.configZone[128]
  atecc.readConfigZone(true); // Debug argument false (OFF)

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

  // if everything is locked up, then configuration is complete, so let's print the public key
  if (atecc.configLockStatus) 
  {
    if(atecc.generatePublicKey() == false)
    {
      Serial.println("Failure to generate This device's Public Key");
      Serial.println();
    }
  }
}
