/*
  This is a library written for the ATECCX08A Criptographic Co-Processor (QWIIC).

  Written by Pete Lewis @ SparkFun Electronics, August 5th, 2019

  The IC uses I2C or 1-wire to communicate. This library only supports I2C.

  https://github.com/sparkfun/SparkFun_ATECCX08A_Arduino_Library

  Do you like this library? Help support SparkFun. Buy a board!

  Development environment specifics:
  Arduino IDE 1.8.10

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "SparkFun_ATECCX08A_Arduino_Library.h"

/** \brief 

	begin(uint8_t i2caddr, TwoWire &wirePort)
	
	returns false if IC does not respond,
	returns true if wake() function is successful
	
	Note, in most SparkFun Arduino Libraries, begin would call a different
	function called isConnected() to check status on the bus, but because 
	this IC will ACK and respond with a status, we are gonna use wakeUp() 
	for the same purpose.
*/

boolean ATECCX08A::begin(uint8_t i2caddr, i2c_t3 &wirePort)
{
  //Bring in the user's choices
  _i2cPort = &wirePort; //Grab which port the user wants us to use

  _i2caddr = i2caddr;

  return ( wakeUp() ); // see if the IC wakes up properly, return responce.
}

/** \brief 

	wakeUp()
	
	This function wakes up the ATECCX08a IC
	Returns TRUE if the IC responds with correct verification
	Message (0x04, 0x11, 0x33, 0x44) 
	The actual status byte we are looking for is the 0x11.
	The complete message is as follows:
	COUNT, DATA, CRC[0], CRC[1].
	0x11 means that it received the wake condition and is goat to goo.
	
	Note, in most SparkFun Arduino Libraries, we would use a different
	function called isConnected(), but because this IC will ACK and
	respond with a status, we are gonna use wakeUp() for the same purpose.
*/

boolean ATECCX08A::wakeUp()
{
  _i2cPort->beginTransmission(0x00); // set up to write to address "0x00",
  // This creates a "wake condition" where SDA is held low for at least tWLO
  // tWLO means "wake low duration" and must be at least 60 uSeconds (which is acheived by writing 0x00 at 100KHz I2C)
  _i2cPort->endTransmission(); // actually send it

  delayMicroseconds(1500); // required for the IC to actually wake up.
  // 1500 uSeconds is minimum and known as "Wake High Delay to Data Comm." tWHI, and SDA must be high during this time.

  // Now let's read back from the IC and see if it reports back good things.
  countGlobal = 0; 
  if(receiveResponseData(4) == false) return false;
  if(checkCount() == false) return false;
  if(checkCrc() == false) return false;
  if(inputBuffer[1] == 0x11) return true;   // If we hear a "0x11", that means it had a successful wake up.
  else return false;
}

/** \brief

	idleMode()
	
	The ATECCX08A goes into the idle mode and ignores all subsequent I/O transitions
	until the next wake flag. The contents of TempKey and RNG Seed registers are retained.
	Idle Power Supply Current: 800uA.
	Note, it will automatically go into sleep mode after watchdog timer has been reached (1.3-1.7sec).
*/

void ATECCX08A::idleMode()
{
  _i2cPort->beginTransmission(_i2caddr); // set up to write to address
  _i2cPort->write(WORD_ADDRESS_VALUE_IDLE); // enter idle command (aka word address - the first part of every communication to the IC)
  _i2cPort->endTransmission(); // actually send it  
}

/** \brief

	getInfo()
	
	This function sends the INFO Command and listens for the correct version (0x50) within the response.
	The Info command has a mode parameter, and in this function we are using the "Revision" mode (0x00)
	At the time of data sheet creation the Info command will return 0x00 0x00 0x50 0x00. For
	all versions of the ECC508A the 3rd byte will always be 0x50. The fourth byte will indicate the
	silicon revision.
*/

boolean ATECCX08A::getInfo()
{
  sendCommand(COMMAND_OPCODE_INFO, 0x00, 0x0000); // param1 - 0x00 (revision mode).

  delay(1); // time for IC to process command and exectute
  
    // Now let's read back from the IC and see if it reports back good things.
  countGlobal = 0; 
  if(receiveResponseData(7, true) == false) return false;
  idleMode();
  if(checkCount() == false) return false;
  if(checkCrc() == false) return false;
  if(inputBuffer[3] == 0x50) return true;   // If we hear a "0x50", that means it had a successful version response.
  else return false;
}

/** \brief

	lockConfig()
	
	This function sends the LOCK Command with the configuration zone parameter, 
	and listens for success response (0x00).
*/

boolean ATECCX08A::lockConfig()
{
  return lock(LOCK_MODE_ZONE_CONFIG);
}

/** \brief

	readConfigZone()
	
	This function reads the entire configuration zone EEPROM memory on the device.
	It stores them for vewieing in a large array called configZone[128].
	In addition to configuration settings, the configuration memory on the IC also
	contains the serial number, revision number, lock statuses, and much more.
	This function also updates global variables for these other things.
*/

boolean ATECCX08A::readConfigZone(boolean debug)
{
  // read block 0, the first 32 bytes of config zone into inputBuffer
  read(ZONE_CONFIG, ADDRESS_CONFIG_READ_BLOCK_0, 32); 
  
  // copy current contents of inputBuffer into configZone[] (for later viewing/comparing)
  memcpy(&configZone[0], &inputBuffer[1], 32);
  
  read(ZONE_CONFIG, ADDRESS_CONFIG_READ_BLOCK_1, 32); 	// read block 1
  memcpy(&configZone[32], &inputBuffer[1], 32); 	// copy block 1
  
  read(ZONE_CONFIG, ADDRESS_CONFIG_READ_BLOCK_2, 32); 	// read block 2
  memcpy(&configZone[64], &inputBuffer[1], 32); 	// copy block 2
  
  read(ZONE_CONFIG, ADDRESS_CONFIG_READ_BLOCK_3, 32); 	// read block 3
  memcpy(&configZone[96], &inputBuffer[1], 32); 	// copy block 3  
  
  // pull out serial number from configZone, and copy to public variable within this instance
  memcpy(&serialNumber[0], &configZone[0], 4); 	// copy SN<0:3> 
  memcpy(&serialNumber[4], &configZone[8], 5); 	// copy SN<4:8> 
  
  // pull out revision number from configZone, and copy to public variable within this instance
  memcpy(&revisionNumber[0], &configZone[4], 4); 	// copy RevNum<0:3>   
  
  // set lock statuses for config, data/otp, and slot 0
  if(configZone[87] == 0x00) configLockStatus = true;
  else configLockStatus = false;
  
  if(configZone[86] == 0x00) dataOTPLockStatus = true;
  else dataOTPLockStatus = false;
  
  if( (configZone[88] & (1<<0) ) == true) slot0LockStatus = false; // LSB is slot 0. if bit set = UN-locked.
  else slot0LockStatus = true;
  
  if(debug)
  {
    Serial.println("configZone: ");
    for (int i = 0; i < sizeof(configZone) ; i++)
    {
      Serial.print(i);
	  Serial.print(": 0x");
	  if((configZone[i] >> 4) == 0) Serial.print("0"); // print preceeding high nibble if it's zero
	  Serial.print(configZone[i], HEX); 
	  Serial.print(" \t0b");
	  for(int bit = 7; bit >= 0; bit--) Serial.print(bitRead(configZone[i],bit)); // print binary WITH preceding '0' bits
	  Serial.println();
    }
    Serial.println();
  }
  
  
  return true;
}

/** \brief

	lockDataAndOTP()
	
	This function sends the LOCK Command with the Data and OTP (one-time-programming) zone parameter, 
	and listens for success response (0x00).
*/

boolean ATECCX08A::lockDataAndOTP()
{
  return lock(LOCK_MODE_ZONE_DATA_AND_OTP);
}

/** \brief

	lockDataSlot0()
	
	This function sends the LOCK Command with the Slot 0 zone parameter, 
	and listens for success response (0x00).
*/

boolean ATECCX08A::lockDataSlot0()
{
  return lock(LOCK_MODE_SLOT0);
}

/** \brief

	lock(byte zone)
	
	This function sends the LOCK Command using the argument zone as parameter 1, 
	and listens for success response (0x00).
*/

boolean ATECCX08A::lock(uint8_t zone)
{
  sendCommand(COMMAND_OPCODE_LOCK, zone, 0x0000);

  delay(32); // time for IC to process command and exectute
  
  // Now let's read back from the IC and see if it reports back good things.
  countGlobal = 0; 
  if(receiveResponseData(4) == false) return false;
  idleMode();
  if(checkCount() == false) return false;
  if(checkCrc() == false) return false;
  if(inputBuffer[1] == 0x00) return true;   // If we hear a "0x00", that means it had a successful lock
  else return false;
}

/** \brief

	lockDataSlot(byte zone)
	
	This function sends the LOCK Command using the argument zone as parameter 1, 
	and listens for success response (0x00).
*/

boolean ATECCX08A::lockDataSlot(int slot)
{
  uint8_t zone = (slot << 2) | 0b10000010;
  sendCommand(COMMAND_OPCODE_LOCK, zone, 0x0000);

  delay(32); // time for IC to process command and exectute
  
  // Now let's read back from the IC and see if it reports back good things.
  countGlobal = 0; 
  if(receiveResponseData(4) == false) return false;
  idleMode();
  if(checkCount() == false) return false;
  if(checkCrc() == false) return false;
  if(inputBuffer[1] == 0x00) return true;   // If we hear a "0x00", that means it had a successful lock
  else return false;
}

/** \brief

	updateRandom32Bytes(boolean debug)
	
    This function pulls a complete random number (all 32 bytes)
    It stores it in a global array called random32Bytes[]
    If you wish to access this global variable and use as a 256 bit random number,
    then you will need to access this array and combine it's elements as you wish.
    In order to keep compatibility with ATmega328 based arduinos,
    We have offered some other functions that return variables more usable (i.e. byte, int, long)
    They are getRandomByte(), getRandomInt(), and getRandomLong().
*/

boolean ATECCX08A::updateRandom32Bytes(boolean debug)
{
  sendCommand(COMMAND_OPCODE_RANDOM, 0x00, 0x0000); 
  // param1 = 0. - Automatically update EEPROM seed only if necessary prior to random number generation. Recommended for highest security.
  // param2 = 0x0000. - must be 0x0000.

  delay(23); // time for IC to process command and exectute

  // Now let's read back from the IC. This will be 35 bytes of data (count + 32_data_bytes + crc[0] + crc[1])

  if(receiveResponseData(35, debug) == false) return false;
  idleMode();
  if(checkCount(debug) == false) return false;
  if(checkCrc(debug) == false) return false;
  
  
  // update random32Bytes[] array
  // we don't need the count value (which is currently the first byte of the inputBuffer)
  for (int i = 0 ; i < 32 ; i++) // for loop through to grab all but the first position (which is "count" of the message)
  {
    random32Bytes[i] = inputBuffer[i + 1];
  }

  if(debug)
  {
    Serial.print("random32Bytes: ");
    for (int i = 0; i < sizeof(random32Bytes) ; i++)
    {
      Serial.print(random32Bytes[i], HEX);
      Serial.print(",");
    }
    Serial.println();
  }
  
  return true;
}

/** \brief

	getRandomByte(boolean debug)
	
    This function returns a random byte.
	It calls updateRandom32Bytes(), then uses the first byte in that array for a return value.
*/

byte ATECCX08A::getRandomByte(boolean debug)
{
  updateRandom32Bytes(debug);
  return random32Bytes[0];
}

/** \brief

	getRandomInt(boolean debug)
	
    This function returns a random Int.
	It calls updateRandom32Bytes(), then uses the first 2 bytes in that array for a return value.
	It bitwize ORS the first two bytes of the array into the return value.
*/

int ATECCX08A::getRandomInt(boolean debug)
{
  updateRandom32Bytes(debug);
  int return_val;
  return_val = random32Bytes[0]; // store first randome byte into return_val
  return_val <<= 8; // shift it over, to make room for the next byte
  return_val |= random32Bytes[1]; // "or in" the next byte in the array
  return return_val;
}

/** \brief

	getRandomLong(boolean debug)
	
    This function returns a random Long.
	It calls updateRandom32Bytes(), then uses the first 4 bytes in that array for a return value.
	It bitwize ORS the first 4 bytes of the array into the return value.
*/

long ATECCX08A::getRandomLong(boolean debug)
{
  updateRandom32Bytes(debug);
  long return_val;
  return_val = random32Bytes[0]; // store first randome byte into return_val
  return_val <<= 8; // shift it over, to make room for the next byte
  return_val |= random32Bytes[1]; // "or in" the next byte in the array
  return_val <<= 8; // shift it over, to make room for the next byte
  return_val |= random32Bytes[2]; // "or in" the next byte in the array
  return_val <<= 8; // shift it over, to make room for the next byte
  return_val |= random32Bytes[3]; // "or in" the next byte in the array
  return return_val;
}

/** \brief

	random(long max)
	
    This function returns a positive random Long between 0 and max
	max can be up to the larges positive value of a long: 2147483647
*/

long ATECCX08A::random(long max)
{
  return random(0, max);
}

/** \brief

	random(long min, long max)
	
    This function returns a random Long with set boundaries of min and max.
	If you flip min and max, it still works!
	Also, it can handle negative numbers. Wahoo!
*/

long ATECCX08A::random(long min, long max)
{
  long randomLong = getRandomLong();
  long halfFSR = (max - min) / 2; // half of desired full scale range
  long midPoint = (max + min) / 2; // where we "start" out output value, then add in a fraction of halfFSR
  float fraction = float(randomLong) / 2147483647;
  return (midPoint + (halfFSR * fraction) );
}

/** \brief

	receiveResponseData(uint8_t length, boolean debug)
	
	This function receives messages from the ATECCX08a IC (up to 128 Bytes)
	It will return true if it receives the correct amount of data and good CRCs.
	What we hear back from the IC is always formatted with the following series of bytes:
	COUNT, DATA, CRC[0], CRC[1]
	Note, the count number includes itself, the num of data bytes, and the two CRC bytes in the total, 
	so a simple response message from the IC that indicates that it heard the wake 
	condition properly is like so:
	EXAMPLE Wake success response: 0x04, 0x11, 0x33, 0x44
	It needs length argument:
	length: length of data to receive (includes count + DATA + 2 crc bytes)
*/

boolean ATECCX08A::receiveResponseData(uint8_t length, boolean debug)
{	

  // pull in data 32 bytes at at time. (necessary to avoid overflow on atmega328)
  // if length is less than or equal to 32, then just pull it in.
  // if length is greater than 32, then we must first pull in 32, then pull in remainder.
  // lets use length as our tracker and we will subtract from it as we pull in data.
  
  countGlobal = 0; // reset for each new message (most important, like wensleydale at a cheese party)
  cleanInputBuffer();
  byte requestAttempts = 0; // keep track of how many times we've attempted to request, to break out if necessary
  
  while(length)
  {
    byte requestAmount; // amount of bytes to request, needed to pull in data 32 bytes at a time
	if(length > 32) requestAmount = 32; // as we have more than 32 to pull in, keep pulling in 32 byte chunks
	else requestAmount = length; // now we're ready to pull in the last chunk.
	_i2cPort->requestFrom(_i2caddr, requestAmount);    // request bytes from slave
	requestAttempts++;

	while (_i2cPort->available())   // slave may send less than requested
	{
	  inputBuffer[countGlobal] = _i2cPort->read();    // receive a byte as character
	  length--; // keep this while loop active until we've pulled in everything
	  countGlobal++; // keep track of the count of the entire message.
	}  
	if(requestAttempts == 20) break; // this probably means that the device is not responding.
  }

  if(debug)
  {
    Serial.print("inputBuffer: ");
	for (int i = 0; i < countGlobal ; i++)
	{
	  Serial.print(inputBuffer[i], HEX);
	  Serial.print(",");
	}
	Serial.println();	  
  }
  return true;
}

/** \brief

	checkCount(boolean debug)
	
	This function checks that the count byte received in the most recent message equals countGlobal
	Call receiveResponseData, and then imeeditately call this to check the count of the complete message.
	Returns true if inputBuffer[0] == countGlobal.
*/

boolean ATECCX08A::checkCount(boolean debug)
{
  if(debug)
  {
    Serial.print("countGlobal: 0x");
	Serial.println(countGlobal, HEX);
	Serial.print("count heard from IC (inpuBuffer[0]): 0x");
    Serial.println(inputBuffer[0], HEX);
  }
  // Check count; the first byte sent from IC is count, and it should be equal to the actual message count
  if(inputBuffer[0] != countGlobal) 
  {
	if(debug) Serial.println("Message Count Error");
	return false;
  }  
  return true;
}

/** \brief

	checkCrc(boolean debug)
	
	This function checks that the CRC bytes received in the most recent message equals a calculated CRCs
	Call receiveResponseData, then call immediately call this to check the CRCs of the complete message.
*/

boolean ATECCX08A::checkCrc(boolean debug)
{
  // Check CRC[0] and CRC[1] are good to go.
  
  atca_calculate_crc(countGlobal-2, inputBuffer);   // first calculate it
  
  if(debug)
  {
    Serial.print("CRC[0] Calc: 0x");
	Serial.println(crc[0], HEX);
	Serial.print("CRC[1] Calc: 0x");
    Serial.println(crc[1], HEX);
  }
  
  if( (inputBuffer[countGlobal-1] != crc[1]) || (inputBuffer[countGlobal-2] != crc[0]) )   // then check the CRCs.
  {
	if(debug) Serial.println("Message CRC Error");
	return false;
  }
  
  return true;
}

/** \brief

	atca_calculate_crc(uint8_t length, uint8_t *data)
	
    This function calculates CRC.
    It was copied directly from the App Note provided from Microchip.
    Note, it seems to be their own unique type of CRC cacluation.
    View the entire app note here:
    http://ww1.microchip.com/downloads/en/AppNotes/Atmel-8936-CryptoAuth-Data-Zone-CRC-Calculation-ApplicationNote.pdf
    \param[in] length number of bytes in buffer
    \param[in] data pointer to data for which CRC should be calculated
*/

void ATECCX08A::atca_calculate_crc(uint8_t length, uint8_t *data)
{
  uint8_t counter;
  uint16_t crc_register = 0;
  uint16_t polynom = 0x8005;
  uint8_t shift_register;
  uint8_t data_bit, crc_bit;
  for (counter = 0; counter < length; counter++) {
    for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1) {
      data_bit = (data[counter] & shift_register) ? 1 : 0;
      crc_bit = crc_register >> 15;
      crc_register <<= 1;
      if (data_bit != crc_bit)
        crc_register ^= polynom;
    }
  }
  crc[0] = (uint8_t) (crc_register & 0x00FF);
  crc[1] = (uint8_t) (crc_register >> 8);
}


/** \brief

	cleanInputBuffer()
	
    This function sets the entire inputBuffer to 0xFFs.
	It is helpful for debugging message/count/CRCs errors.
*/

void ATECCX08A::cleanInputBuffer()
{
  for (int i = 0; i < sizeof(inputBuffer) ; i++)
  {
    inputBuffer[i] = 0xFF;
  }
}

/** \brief

	createNewKeyPair(uint16_t slot)
	
    This function sends the command to create a new key pair (private AND public)
	in the slot designated by argument slot (default slot 0).
	Sparkfun Default Configuration Sketch calls this, and then locks the data/otp zones and slot 0.
*/

boolean ATECCX08A::createNewKeyPair(uint16_t slot)
{  
  sendCommand(COMMAND_OPCODE_GENKEY, GENKEY_MODE_NEW_PRIVATE, slot);

  delay(115); // time for IC to process command and exectute

  // Now let's read back from the IC.
  
  if(receiveResponseData(64 + 2 + 1) == false) return false; // public key (64), plus crc (2), plus count (1)
  idleMode();
  boolean checkCountResult = checkCount();
  boolean checkCrcResult = checkCrc();
  
  
  // update publicKey64Bytes[] array
  if(checkCountResult && checkCrcResult) // check that it was a good message
  {
	// we don't need the count value (which is currently the first byte of the inputBuffer)
	for (int i = 0 ; i < 64 ; i++) // for loop through to grab all but the first position (which is "count" of the message)
	{
	  publicKey64Bytes[i] = inputBuffer[i + 1];
	}
	return true;
  }
  else return false;
}

/** \brief

	generatePublicKey(uint16_t slot, boolean debug)

    This function uses the GENKEY command in "Public Key Computation" mode.
	
    Generates an ECC public key based upon the private key stored in the slot defined by the KeyID
	parameter (aka slot). Defaults to slot 0. 
	
	Note, if you haven't created a private key in the slot already, then this will fail.
	
	The generated public key is read back from the device, and then copied from inputBuffer to 
	a global variable named publicKey64Bytes for later use.
*/

boolean ATECCX08A::generatePublicKey(uint16_t slot, boolean debug)
{
  sendCommand(COMMAND_OPCODE_GENKEY, GENKEY_MODE_PUBLIC, slot);

  delay(115); // time for IC to process command and exectute

  // Now let's read back from the IC.
  
  if(receiveResponseData(64 + 2 + 1) == false) return false; // public key (64), plus crc (2), plus count (1)
  idleMode();
  boolean checkCountResult = checkCount();
  boolean checkCrcResult = checkCrc();
  
  // update publicKey64Bytes[] array
  if(checkCountResult && checkCrcResult) // check that it was a good message
  {  
    // we don't need the count value (which is currently the first byte of the inputBuffer)
    for (int i = 0 ; i < 64 ; i++) // for loop through to grab all but the first position (which is "count" of the message)
    {
      publicKey64Bytes[i] = inputBuffer[i + 1];
    }
	
	if(debug)
	{
		Serial.println("This device's Public Key:");
		Serial.println();
		Serial.println("uint8_t publicKey[64] = {");
		for (int i = 0; i < sizeof(publicKey64Bytes) ; i++)
		{
		  Serial.print("0x");
		  if((publicKey64Bytes[i] >> 4) == 0) Serial.print("0"); // print preceeding high nibble if it's zero
		  Serial.print(publicKey64Bytes[i], HEX);
		  if(i != 63) Serial.print(", ");
		  if((63-i) % 16 == 0) Serial.println();
		}
		Serial.println("};");
		Serial.println();
	}
	return true;
  }
  else return false;
}

/** \brief

	read(uint8_t zone, uint16_t address, uint8_t length, boolean debug)

    Reads data from the IC at a specific zone and address.
	Your data response will be available at inputBuffer[].
	
	For more info on address encoding, see datasheet pg 58.
*/

boolean ATECCX08A::read(uint8_t zone, uint16_t address, uint8_t length, boolean debug)
{
  // adjust zone as needed for whether it's 4 or 32 bytes length read
  // bit 7 of zone needs to be set correctly 
  // (0 = 4 Bytes are read) 
  // (1 = 32 Bytes are read)
  if(length == 32) 
  {
	zone |= 0b10000000; // set bit 7
  }
  else if(length == 4)
  {
	zone &= ~0b10000000; // clear bit 7
  }
  else
  {
	return 0; // invalid length, abort.
  }

  sendCommand(COMMAND_OPCODE_READ, zone, address);
  
  delay(1); // time for IC to process command and exectute

  // Now let's read back from the IC. 
  
  if(receiveResponseData(length + 3, debug) == false) return false;
  idleMode();
  if(checkCount(debug) == false) return false;
  if(checkCrc(debug) == false) return false;
  
  return true;
}

/** \brief

	write(uint8_t zone, uint16_t address, uint8_t *data, uint8_t length_of_data)

    Writes data to a specific zone and address on the IC.
	
	For more info on zone and address encoding, see datasheet pg 58.
*/

boolean ATECCX08A::write(uint8_t zone, uint16_t address, uint8_t *data, uint8_t length_of_data)
{
  // adjust zone as needed for whether it's 4 or 32 bytes length write
  // bit 7 of param1 needs to be set correctly 
  // (0 = 4 Bytes are written) 
  // (1 = 32 Bytes are written)
  if(length_of_data == 32) 
  {
	zone |= 0b10000000; // set bit 7
  }
  else if(length_of_data == 4)
  {
	zone &= ~0b10000000; // clear bit 7
  }
  else
  {
	return 0; // invalid length, abort.
  }
 
  sendCommand(COMMAND_OPCODE_WRITE, zone, address, data, length_of_data);

  delay(26); // time for IC to process command and exectute
  
  // Now let's read back from the IC and see if it reports back good things.
  countGlobal = 0; 
  if(receiveResponseData(4) == false) return false;
  idleMode();
  if(checkCount() == false) return false;
  if(checkCrc() == false) return false;
  if(inputBuffer[1] == 0x00) return true;   // If we hear a "0x00", that means it had a successful write
  else return false;
}

/** \brief

	createSignature(uint8_t *data, uint16_t slot)

    Creates a 64-byte ECC signature on 32 bytes of data.
	Defautes to use private key located in slot 0.
	Your signature will be available at global variable signature[].
	
	Note, the IC actually needs you to store your data in a temporary memory location
	called TempKey. This function first loads TempKey, and then signs TempKey. Then it 
	receives the signature and copies it to signature[].
*/

boolean ATECCX08A::createSignature(uint8_t *data, uint16_t slot, bool debug)
{
  boolean loadTempKeyResult = loadTempKey(data);
  if (debug) {
    Serial.print("loadTempKeyResult: ");
    Serial.println(loadTempKeyResult);
  }
  boolean signTempKeyResult = signTempKey(slot, debug);
  if (debug) {
    Serial.print("signTempKeyResult: ");
    Serial.println(signTempKeyResult);
  }
  if(loadTempKeyResult && signTempKeyResult) return true;
  else return false;
}

/** \brief

	loadTempKey(uint8_t *data)

	Writes 32 bytes of data to memory location "TempKey" on the IC.
	Note, the data is provided externally by you, the user, and is included in the
	command NONCE.

    We will use the NONCE command in passthrough mode to load tempKey with our data (aka message).
    Note, the datasheet warns that this does not provide protection agains replay attacks,
    but we will protect again this because our server (Bob) is going to send us it's own unique random TOKEN,
    when it requests data, and this will allow us to create a unique data + signature for every communication.
*/

boolean ATECCX08A::loadTempKey(uint8_t *data)
{
  sendCommand(COMMAND_OPCODE_NONCE, NONCE_MODE_PASSTHROUGH, 0x0000, data, 32);
  
  // note, param2 is 0x0000 (and param1 is PASSTHROUGH), so OutData will be just a single byte of zero upon completion.
  // see ds pg 77 for more info

  delay(7); // time for IC to process command and exectute

  // Now let's read back from the IC.
  
  if(receiveResponseData(4) == false) return false; // responds with "0x00" if NONCE executed properly
  idleMode();
  boolean checkCountResult = checkCount();
  boolean checkCrcResult = checkCrc();
  
  if( (checkCountResult == false) || (checkCrcResult == false) ) return false;
  
  if(inputBuffer[1] == 0x00) return true;   // If we hear a "0x00", that means it had a successful nonce
  else return false;
}

/** \brief

	signTempKey(uint16_t slot)

	Create a 64 byte ECC signature for the contents of TempKey using the private key in Slot.
	Default slot is 0.
	
	The response from this command (the signature) is stored in global varaible signature[].
*/

boolean ATECCX08A::signTempKey(uint16_t slot, bool debug)
{
  sendCommand(COMMAND_OPCODE_SIGN, SIGN_MODE_TEMPKEY, slot);

  delay(100); // time for IC to process command and exectute

  // Now let's read back from the IC.

  if(receiveResponseData(64 + 2 + 1) == false) return false; // signature (64), plus crc (2), plus count (1)
  idleMode();
  boolean checkCountResult =  checkCount();
  boolean checkCrcResult = checkCrc();
  
  // update signature[] array and print it to serial terminal nicely formatted for easy copy/pasting between sketches
  if(checkCountResult && checkCrcResult) // check that it was a good message
  {  
    // we don't need the count value (which is currently the first byte of the inputBuffer)
    for (int i = 0 ; i < 64 ; i++) // for loop through to grab all but the first position (which is "count" of the message)
    {
      signature[i] = inputBuffer[i + 1];
    }
  if (debug){
    Serial.println();
    Serial.println("uint8_t signature[64] = {");
    for (int i = 0; i < sizeof(signature) ; i++)
    {
    Serial.print("0x");
    if((signature[i] >> 4) == 0) Serial.print("0"); // print preceeding high nibble if it's zero
      Serial.print(signature[i], HEX);
      if(i != 63) Serial.print(", ");
    if((63-i) % 16 == 0) Serial.println();
    }
  Serial.println("};");
  }
	return true;
  }
  else return false;
}

/** \brief

	verifySignature(uint8_t *message, uint8_t *signature, uint8_t *publicKey)
	
	Verifies a ECC signature using the message, signature and external public key.
	Returns true if successful.
	
	Note, it acutally uses loadTempKey, then uses the verify command in "external public key" mode.
*/

boolean ATECCX08A::verifySignature(uint8_t *message, uint8_t *signature, uint8_t *publicKey)
{
  // first, let's load the message into TempKey on the device, this uses NONCE command in passthrough mode.
  boolean loadTempKeyResult = loadTempKey(message);
  if(loadTempKeyResult == false) 
  {
    Serial.println("Load TempKey Failure");
    return false;
  }

  // We can only send one *single* data array to sendCommand as Param2, so we need to combine signature and public key.
  uint8_t data_sigAndPub[128]; 
  memcpy(&data_sigAndPub[0], &signature[0], 64);	// append signature
  memcpy(&data_sigAndPub[64], &publicKey[0], 64);	// append external public key
  
  sendCommand(COMMAND_OPCODE_VERIFY, VERIFY_MODE_EXTERNAL, VERIFY_PARAM2_KEYTYPE_ECC, data_sigAndPub, sizeof(data_sigAndPub));

  delay(58); // time for IC to process command and exectute

  // Now let's read back from the IC.
  
  if(receiveResponseData(4) == false) return false;
  idleMode();
  boolean checkCountResult = checkCount();
  boolean checkCrcResult = checkCrc();
  
  if( (checkCountResult == false) || (checkCrcResult == false) ) return false;
  
  if(inputBuffer[1] == 0x00) return true;   // If we hear a "0x00", that means it had a successful verify
  else return false;
}

/** \brief

	writeConfigSparkFun()
	
	Writes the necessary configuration settings to the IC in order to work with the SparkFun Arduino Library examples.
	For key slots 0 and 1, this enables ECC private key pairs,public key generation, and external signature verifications.
	
	Returns true if write commands were successful.
*/

boolean ATECCX08A::writeConfigSparkFun()
{
  // keep track of our write command results.
  boolean result1; 
  boolean result2;
  
  // set keytype on slot 0 and 1 to 0x3300
  // Lockable, ECC, PuInfo set (public key always allowed to be generated), contains a private Key
  uint8_t data1[] = {0x33, 0x00, 0x33, 0x00}; // 0x3300 sets the keyconfig.keyType, see datasheet pg 20
  result1 = write(ZONE_CONFIG, (96 / 4), data1, 4);
  // set slot config on slot 0 and 1 to 0x8320
  // EXT signatures, INT signatures, IsSecret, Write config never
  uint8_t data2[] = {0x87, 0x20, 0x8F, 0x20}; // for slot config bit definitions see datasheet pg 20
  result2 = write(ZONE_CONFIG, (20 / 4), data2, 4);
  
  return (result1 && result2);
}

/** \brief

	sendCommand(uint8_t command_opcode, uint8_t param1, uint16_t param2, uint8_t *data, size_t length_of_data)
	
	Generic function for sending commands to the IC. 
	
	This function handles creating the "total transmission" to the IC.
	This contains WORD_ADDRESS_VALUE, COUNT, OPCODE, PARAM1, PARAM2, DATA (optional), and CRCs.
	
	Note, it always calls the "wake()" function, assuming that you have let the IC fall asleep (default 1.7 sec)
	
	Note, for anything other than a command (reset, sleep and idle), you need a different "Word Address Value",
	So those specific transmissions are handled in unique functions.
*/

boolean ATECCX08A::sendCommand(uint8_t command_opcode, uint8_t param1, uint16_t param2, uint8_t *data, size_t length_of_data)
{
  // build packet array (total_transmission) to send a communication to IC, with opcode COMMAND
  // It expects to see: word address, count, command opcode, param1, param2, data (optional), CRC[0], CRC[1]
  
  uint8_t total_transmission_length;
  total_transmission_length = (1 + 1 + 1 + 1 + 2 + length_of_data + 2); 
  // word address val (1) + count (1) + command opcode (1) param1 (1) + param2 (2) data (0-?) + crc (2)

  uint8_t total_transmission[total_transmission_length];
  total_transmission[0] = WORD_ADDRESS_VALUE_COMMAND; 		// word address value (type command)
  total_transmission[1] = total_transmission_length-1; 		// count, does not include itself, so "-1"
  total_transmission[2] = command_opcode; 			// command
  total_transmission[3] = param1;							// param1
  memcpy(&total_transmission[4], &param2, sizeof(param2));	// append param2 
  memcpy(&total_transmission[6], &data[0], length_of_data);	// append data
  
  // update CRCs
  uint8_t packet_to_CRC[total_transmission_length-3]; // minus word address (1) and crc (2).
  memcpy(&packet_to_CRC[0], &total_transmission[1], (total_transmission_length-3)); // copy over just what we need to CRC starting at index 1
  
  //  Serial.println("packet_to_CRC: ");
  //  for (int i = 0; i < sizeof(packet_to_CRC) ; i++)
  //  {
  //  Serial.print(packet_to_CRC[i], HEX);
  //  Serial.print(",");
  //  }
  //  Serial.println();
  
  atca_calculate_crc((total_transmission_length-3), packet_to_CRC); // count includes crc[0] and crc[1], so we must subtract 2 before creating crc
  //Serial.println(crc[0], HEX);
  //Serial.println(crc[1], HEX);

  memcpy(&total_transmission[total_transmission_length-2], &crc[0], 2);  // append crcs

  wakeUp();
  
  _i2cPort->beginTransmission(_i2caddr);
  _i2cPort->write(total_transmission, total_transmission_length); 
  _i2cPort->endTransmission();
  
  return true;
}

boolean ATECCX08A::ECDH(uint8_t *data, uint8_t mode, uint16_t slot)
{
  sendCommand(COMMAND_OPCODE_ECDH, mode, slot, data, 64);
  

  delay(100); // time for IC to process command and exectute

  // Now let's read back from the IC.
  if(receiveResponseData(4) == false) return false;  
  idleMode();
  if(checkCount() == false) return false;
  if(checkCrc() == false) return false;
  if(inputBuffer[1] == 0x00) {
  Serial.println("Succesfully Calculated ECDH Shared Secret and Loaded into TempKey");
  }
  else return false;
}
  
boolean ATECCX08A::AES_ECB(uint8_t *data, uint16_t slot)
{
	sendCommand(COMMAND_OPCODE_AES_ECB, AES_ECB_ENCRYPT, slot, data, 16);
	delay(100);

	if(receiveResponseData(19) == false) return false;  
	idleMode();
	boolean checkCountResult = checkCount();
	boolean checkCrcResult = checkCrc();

	if(checkCountResult && checkCrcResult) // check that it was a good message
  {  
    // we don't need the count value (which is currently the first byte of the inputBuffer)
    for (int i = 0 ; i < 16 ; i++) // for loop through to grab all but the first position (which is "count" of the message)
    {
      AES_buffer[i] = inputBuffer[i + 1];
    }
  
  Serial.println();
    Serial.println("uint8_t AES_buffer[16] = {");
    for (int i = 0; i < sizeof(AES_buffer) ; i++)
    {
    Serial.print("0x");
    if((AES_buffer[i] >> 4) == 0) Serial.print("0"); // print preceeding high nibble if it's zero
      Serial.print(AES_buffer[i], HEX);
      if(i != 15) Serial.print(", ");
    if((15-i) % 16 == 0) Serial.println();
    }
  Serial.println("};");
  return true;
  }
  else return false;

}


boolean ATECCX08A::writeProvisionConfig()
{
  // keep track of our write command results.
  boolean result1; 
  boolean result2;
  boolean result3;
  boolean result4;


  // set keytype on slot 0 and 1 to 0x3300
  // Lockable, ECC, PuInfo set (public key always allowed to be generated), contains a private Key
  uint8_t data1[] = {0x33, 0x00, 0x33, 0x00}; // 0x3300 sets the keyconfig.keyType, see datasheet pg 20
  result1 = write(ZONE_CONFIG, (96 / 4), data1, 4);
  // set slot config on slot 0 and 1 to 0x8720
  // EXT signatures, INT signatures, IsSecret, Write config never, ECDH allowed
  uint8_t data2[] = {0x87, 0x20, 0x87, 0x20}; 
  result2 = write(ZONE_CONFIG, (20 / 4), data2, 4);

  //Now set slotconfig and keyconfig for public key slot
  // set keytype on slot 10 and 11 
  //keyconfig for slot 10: no reqAuth, no ReqRandom, individual slot lockable, P256 ECC key type, not priv key
  //keyconfig for slot 11: no reqAuth, no ReqRandom, individual slot lockable, P256 ECC key type, not priv key
  uint8_t data3[] = {0x30, 0x00, 0x30, 0x00}; 
  result3 = write(ZONE_CONFIG, (116 / 4), data3, 4);

  // set slot config on slot 10 and 11 
  //slotconfig for slot 10: is secret, not encryptread, no usage limitation, can be used by all commands, write config never
  //slotconfig for slot 11: is secret, not encryptread, no usage limitation, can be used by all commands, write config never
  uint8_t data4[] = {0x00, 0x20, 0x00, 0x20}; 
  result4 = write(ZONE_CONFIG, (40 / 4), data4, 4);


  return (result1 && result2 && result3 && result4);
}


boolean ATECCX08A::loadPublicKey(uint8_t *data, bool debug)
{
	uint8_t public_x[32];
	uint8_t public_y[32];
	for(int i =0; i <32; i++)
	{
		public_x[i]=data[i];
		public_y[i]=data[i+32];
	}

	//Now Write first 32 bytes of public key to slot 10
	sendCommand(COMMAND_OPCODE_WRITE, WRITE_DATA_32, ADDRESS_DATA_READ_SLOT10_BLOCK_0, public_x, 32);
	delay(100);
	if(receiveResponseData(4) == false) return false;
	idleMode();
	if(checkCount() == false) return false;
	if(checkCrc() == false) return false;
	if(inputBuffer[1] == 0x00) {
	if (debug) Serial.println("Loaded Public Key X Component Successfully");
	//return true;   // If we hear a "0x00", that means it had a successful write
	}

	//Now Write second 32 bytes of public key to slot 10
	sendCommand(COMMAND_OPCODE_WRITE, WRITE_DATA_32, ADDRESS_DATA_READ_SLOT10_BLOCK_1, public_y, 32);
	delay(100);
	if(receiveResponseData(4) == false) return false;
	idleMode();
	if(checkCount() == false) return false;
	if(checkCrc() == false) return false;
	if(inputBuffer[1] == 0x00) {
	if (debug) Serial.println("Loaded Public Key Y Component Successfully");
	return true;   // If we hear a "0x00", that means it had a successful write
	}
	else return false;
}

boolean ATECCX08A::readPublicKey(boolean debug)
{
  // read block 0, the first 32 bytes of slot10 into inputBuffer
  read(ZONE_DATA, ADDRESS_DATA_READ_SLOT10_BLOCK_0, 32); 
  // copy current contents of inputBuffer into storedPublicKey[] (for later viewing/comparing)
  memcpy(&storedPublicKey[0], &inputBuffer[1], 32);

  // read block 0, the first 32 bytes of slot10 into inputBuffer
  read(ZONE_DATA, ADDRESS_DATA_READ_SLOT10_BLOCK_1, 32); 
  // copy current contents of inputBuffer into storedPublicKey[] (for later viewing/comparing)
  memcpy(&storedPublicKey[32], &inputBuffer[1], 32);

  if(debug)
  {
    Serial.println("storedPublicKey: ");
    for (int i = 0; i < sizeof(storedPublicKey) ; i++)
    {
      Serial.print(i);
    Serial.print(": 0x");
    if((storedPublicKey[i] >> 4) == 0) Serial.print("0"); // print preceeding high nibble if it's zero
    Serial.print(storedPublicKey[i], HEX); 
    Serial.print(" \t0b");
    for(int bit = 7; bit >= 0; bit--) Serial.print(bitRead(storedPublicKey[i],bit)); // print binary WITH preceding '0' bits
    Serial.println();
    }
    Serial.println();
  }
}













































