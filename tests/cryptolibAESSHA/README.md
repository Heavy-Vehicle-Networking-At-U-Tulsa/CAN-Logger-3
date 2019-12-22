# Arduino Test Code for Hardware Encryption
This sketch and supporting files leverages the on-board memory mapped cryptographic acceleration unit (mmCAU) in the Teensy 3.6. The files used in here were derived or copied from three sources:

  1. The idea for the test code came from https://github.com/manitou48/teensy3/blob/master/cryptolib.ino
  2. CAUAP: Crypto Acceleration Unit: CAU and mmCAU software library https://www.nxp.com/products/processors-and-microcontrollers/additional-processors-and-mcus/coldfire-plus-coldfire/crypto-acceleration-unit-cau-and-mmcau-software-library:CAUAP
  3. To make the library calls compativble with Arduino, use the header file from https://github.com/PaulStoffregen/CryptoAccel

The test code determines the speed by which a block of 512 bytes can be encrypted. 

Note: this sketch does not randomize the initialization vector or AES key and should not be used to protect anything. 