/* K66F  CAU tests   SHA256  AES-CBC
crypto assist co-processor
Uses 512 Byte block examples
*/
#include "CryptoAccel.h" //Makes it arduino compatible
#include "cau_api.h"

#define data_size 512
#define AES_ROUNDS 10
unsigned int i, t, errs;
unsigned char mdstate[16], data[data_size], cipher_text[data_size], clear_text[data_size];
unsigned int shastate[8];
unsigned char aeskey[16], keysched[4 * 44], in[16], out[16], iv[16], init_vector[16];
char str[16];

void setup() {
  Serial.begin(9600);
  for (i = 0; i < sizeof(data); i++) data[i] = i & 0xff;
  for (i = 0; i < sizeof(aeskey); i++)  aeskey[i] = 0x60; // also des key with odd parity 
  for (i = 0; i < sizeof(init_vector); i++)  init_vector[i] = 0x55;
}

void aes_cbc_encrypt(const unsigned char *data, unsigned char *cipher_text){
  //Data length should be a multiple of 16 bytes
  // Need to initialize "out" with the initialization vector
  for (uint32_t j=0; j < data_size; j+=16){
    for (uint8_t i = 0; i < 16; i++){
      in[i] = data[j+i] ^ out[i];
    }
    cau_aes_encrypt (in, keysched, AES_ROUNDS, out); // # 16-byte block
    memcpy(&cipher_text[j],out,16);
  }
}

void aes_cbc_decrypt(unsigned char *clear_text, const unsigned char *cipher_text){
  //Data length should be a multiple of 16 bytes
  // Need to initialize "iv" with the initialization vector
  for (uint32_t j=0; j < data_size; j+=16){
    cau_aes_decrypt (&cipher_text[j], keysched, AES_ROUNDS, out); 
    for (uint8_t i = 0; i < 16; i++){
      clear_text[j+i] = out[i] ^ iv[i];
    }
    memcpy(iv,&cipher_text[j],16);
  }
}


void loop() {
  
  Serial.println("SHA-256 State:");
  cau_sha256_initialize_output(shastate);
  for (i = 0; i < 8; i++) {
    sprintf(str, "%08X ", shastate[i]);
    Serial.print(str);
  } Serial.println();
  
  t = micros();
  cau_sha256_update (data, sizeof(data) / 64, shastate); // # 64-byte blocks
  t = micros() - t;
  
  sprintf(str, "sha256: %d bytes in %u us   KBs  ", sizeof(data), t);
  Serial.print(str);
  Serial.println(1000.*sizeof(data) / t);
  for (i = 0; i < 8; i++) {
    sprintf(str, "%08x ", shastate[i]);
    Serial.print(str);
  } Serial.println();

  Serial.println("AES-128:");
  t = micros();
  cau_aes_set_key(aeskey, 128, keysched);
  t = micros() - t;
  Serial.print("aes set key microsec "); Serial.println(t);
  //printf("aes set key  %u us\n",t);
  t = micros();
  cau_aes_encrypt (in, keysched, AES_ROUNDS, cipher_text); // # 16-byte block
  t = micros() - t;
  sprintf(str, "aes %d bytes %u us  KBs  ", sizeof(in), t); Serial.print(str);
  Serial.println(1000.*sizeof(in) / t);
  cau_aes_decrypt (cipher_text, keysched, AES_ROUNDS, iv); //  decrypt test
  errs = 0;
  for (i = 0; i < 16; i++) if (in[i] != iv[i]) errs++;
  Serial.print("aes errs "); Serial.println(errs);
  
  // CBC XOR init_vector or cipher_textput with plain, our sketch does 4 blocks
  Serial.print("\nAES Key: ");
  for (i = 0; i < sizeof(aeskey); i++) {
    sprintf(str, "%02x", aeskey[i]);
    Serial.print(str);
  } Serial.println();
  
  memcpy(out,init_vector,16);
  Serial.print("AES IV: ");
  for (i = 0; i < sizeof(init_vector); i++) {
    sprintf(str, "%02x", init_vector[i]);
    Serial.print(str);
  } Serial.println();

  Serial.print("Plain  Text: ");
  for (i = 0; i < sizeof(data); i++) {
    sprintf(str, "%02x", data[i]);
    Serial.print(str);
  } Serial.println();
  
  t = micros();
  aes_cbc_encrypt(data,cipher_text);
  t = micros() - t;
  Serial.print("Cipher Text: ");
  for (i = 0; i < sizeof(cipher_text); i++) {
    sprintf(str, "%02x", cipher_text[i]);
    Serial.print(str);
  } Serial.println();

   
  sprintf(str, "aes cbc encrypt %d bytes %u us, KBs ", sizeof(data), t);
  Serial.print(str);
  Serial.println(1000.*sizeof(data) / t);
  
  t = micros();
  memcpy(iv,init_vector,16);
  aes_cbc_decrypt(clear_text, cipher_text);
  t = micros() - t;
  Serial.print("Clear Text: ");
  for (i = 0; i < sizeof(clear_text); i++) {
    sprintf(str, "%02x", clear_text[i]);
    Serial.print(str);
  } Serial.println();

   
  sprintf(str, "aes cbc decrypt %d bytes %u us, KBs ", sizeof(clear_text), t);
  Serial.print(str);
  Serial.println(1000.*sizeof(clear_text) / t);

  errs = 0;
  for (i = 0; i < sizeof(clear_text); i++) if (data[i] != clear_text[i]) errs++;
  Serial.print("AES CBC Errors: "); Serial.println(errs);
 
  delay(5000);
}
