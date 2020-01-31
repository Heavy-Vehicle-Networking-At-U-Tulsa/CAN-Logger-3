/*
 * AES 128 CBC Mode Test
 * 
 * Arduino Sketch for testing cryptographic function AES-128 CBC against NIST test vectors
 * using the crypto acceleration unit on teensy 3.6
 * 
 * Test vectors are from NIST: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * 
 * Written by Duy Van
 * Colorado State University
 * Department of Systems Engineering
 * 
 * 31 Jan 2020
 * 
 */

//included libraries 
#include "CryptoAccel.h" //Makes the cryptographic acceleration hardware arduino compatible

#define AES_128_NROUNDS 10
#define BUFFER_SIZE 64
#define block_size 16
unsigned char cipher_text[BUFFER_SIZE], clear_text[BUFFER_SIZE];
unsigned char data_to_encrypt[BUFFER_SIZE], data_to_decrypt[BUFFER_SIZE];
unsigned char keysched[4 * 44], in[16], out[16], iv[16];
char str[16];
int i;

//Initialization Vector Input
unsigned char init_vector[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 
                                 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

//AES Key
unsigned char aeskey[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6, 
                            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

//Input Data to Encrypt in 4 blocks
unsigned char data_to_encrypt_block_1[block_size] =
              {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
               0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
unsigned char data_to_encrypt_block_2[block_size] =
              {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
               0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
unsigned char data_to_encrypt_block_3[block_size] =
              {0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
               0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef};
unsigned char data_to_encrypt_block_4[block_size] =
              {0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
               0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};



//Input Data to Decrypt in 4 blocks
unsigned char data_to_decrypt_block_1[block_size] =
              {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
               0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d};
unsigned char data_to_decrypt_block_2[block_size] =
              {0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,
               0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2};
unsigned char data_to_decrypt_block_3[block_size] =
              {0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b,
               0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16};
unsigned char data_to_decrypt_block_4[block_size] =
              {0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09,
               0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7};
               


//AES CBC encrypt funtion
void aes_cbc_encrypt(const unsigned char *data, unsigned char *cipher_text){
  //Data length should be a multiple of 16 bytes
  // Need to initialize out with the initialization vector
  for (uint32_t j=0; j < BUFFER_SIZE; j+=16){
    for (uint8_t i = 0; i < 16; i++){
      in[i] = data[j+i] ^ out[i];
    }
    mmcau_aes_encrypt (in, keysched, AES_128_NROUNDS, out); // # 16-byte block
    memcpy(&cipher_text[j],out,16);
  }
}

//AES CBC decrypt function
void aes_cbc_decrypt(unsigned char *clear_text, const unsigned char *cipher_text){
  //Data length should be a multiple of 16 bytes
  // Need to initialize "iv" with the initialization vector
  for (uint32_t j=0; j < BUFFER_SIZE; j+=16){
    mmcau_aes_decrypt (&cipher_text[j], keysched, AES_128_NROUNDS, out); 
    for (uint8_t i = 0; i < 16; i++){
      clear_text[j+i] = out[i] ^ iv[i];
    }
    memcpy(iv,&cipher_text[j],16);
  }
}

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);
  delay(1000);
  //Print out initial data
  Serial.print("AES KEY: ");
  for (i=0;i<sizeof(aeskey);i++){
    sprintf(str,"%02X",aeskey[i]);
    Serial.print(str);
  }

  Serial.print("\nIV: ");
  for (i=0;i<sizeof(init_vector);i++){
    sprintf(str,"%02X",init_vector[i]);
    Serial.print(str);
  }
  
  for(i =0; i<block_size; i++){
  data_to_encrypt[i] = data_to_encrypt_block_1[i];
  data_to_encrypt[i+block_size*1] = data_to_encrypt_block_2[i];
  data_to_encrypt[i+block_size*2] = data_to_encrypt_block_3[i];
  data_to_encrypt[i+block_size*3] = data_to_encrypt_block_4[i];
}
  Serial.print("\nData to Encrypt: ");
  for (i=0;i<BUFFER_SIZE;i++){
    sprintf(str,"%02X",data_to_encrypt[i]);
    Serial.print(str);
  }

  for(i =0; i<block_size; i++){
  data_to_decrypt[i] = data_to_decrypt_block_1[i];
  data_to_decrypt[i+block_size*1] = data_to_decrypt_block_2[i];
  data_to_decrypt[i+block_size*2] = data_to_decrypt_block_3[i];
  data_to_decrypt[i+block_size*3] = data_to_decrypt_block_4[i];
}
Serial.print("\nData to Decrypt: ");
  for (i=0;i<BUFFER_SIZE;i++){
    sprintf(str,"%02X",data_to_decrypt[i]);
    Serial.print(str);
  }

//Encryption and Decryption
Serial.println();
Serial.print("\nAES-128 CBC Encryption:");
mmcau_aes_set_key(aeskey,128,keysched);//Set key
memcpy(out,init_vector,16); //Load IV
aes_cbc_encrypt(data_to_encrypt,cipher_text);

Serial.print("\nBlock 1 Cipher Text: ");
for (i=0;i<block_size;i++){
    sprintf(str,"%02X",cipher_text[i]);
    Serial.print(str);
  }
Serial.print("\nTest Vector Block 1: 7649abac8119b246cee98e9b12e9197d");

Serial.print("\nBlock 2 Cipher Text: ");
for (i=0;i<block_size;i++){
    sprintf(str,"%02X",cipher_text[i+block_size*1]);
    Serial.print(str);
  }
Serial.print("\nTest Vector Block 2: 5086cb9b507219ee95db113a917678b2");

Serial.print("\nBlock 3 Cipher Text: ");
for (i=0;i<block_size;i++){
    sprintf(str,"%02X",cipher_text[i+block_size*2]);
    Serial.print(str);
  }
Serial.print("\nTest Vector Block 3: 73bed6b8e3c1743b7116e69e22229516");

Serial.print("\nBlock 4 Cipher Text: ");
for (i=0;i<block_size;i++){
    sprintf(str,"%02X",cipher_text[i+block_size*3]);
    Serial.print(str);
  }
Serial.println("\nTest Vector Block 4: 3ff1caa1681fac09120eca307586e1a7");


Serial.print("\nAES-128 CBC Decryption:");

memcpy(iv,init_vector,16);; //Load IV
aes_cbc_decrypt(clear_text,data_to_decrypt);

Serial.print("\nBlock 1 Clear Text: ");
for (i=0;i<block_size;i++){
    sprintf(str,"%02X",clear_text[i]);
    Serial.print(str);
  }
Serial.print("\nTest Vector Block 1: 6bc1bee22e409f96e93d7e117393172a");

Serial.print("\nBlock 2 Clear Text: ");
for (i=0;i<block_size;i++){
    sprintf(str,"%02X",clear_text[i+block_size*1]);
    Serial.print(str);
  }
Serial.print("\nTest Vector Block 2: ae2d8a571e03ac9c9eb76fac45af8e51");

Serial.print("\nBlock 3 Clear Text: ");
for (i=0;i<block_size;i++){
    sprintf(str,"%02X",clear_text[i+block_size*2]);
    Serial.print(str);
  }
Serial.print("\nTest Vector Block 3: 30c81c46a35ce411e5fbc1191a0a52ef");

Serial.print("\nBlock 4 Clear Text: ");
for (i=0;i<block_size;i++){
    sprintf(str,"%02X",clear_text[i+block_size*3]);
    Serial.print(str);
  }
Serial.println("\nTest Vector Block 4: f69f2445df4f9b17ad2b417be66c3710");

}

void loop() {
  // put your main code here, to run repeatedly:

}
