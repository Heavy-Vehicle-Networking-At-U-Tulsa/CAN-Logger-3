#include <sha256.h>

void setup() {
  delay(150);

  Serial.println("Test vector for SHA256");
  Serial.println("");
  
  Sha256* sha256Instance;
  BYTE hash[SHA256_BLOCK_SIZE];
  char texthash[2*SHA256_BLOCK_SIZE+1];


  
  BYTE text1[]="";
  const char hash_text1[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  
  BYTE text2[]="abc";
  const char hash_text2[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  
  BYTE text3[]="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  const char hash_text3[] = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
  
  BYTE text4[]="abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  const char hash_text4[] = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1";
  
  BYTE text5[]="This is exactly 64 bytes long, not counting the terminating byte";
  const char hash_text5[] = "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8";
  
  BYTE text6[]="For this sample, this 63-byte string will be used as input data";
  const char hash_text6[] = "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342";
  
  BYTE text7[]="And this textual data, astonishing as it may appear, is exactly 128 bytes in length, as are both SHA-384 and SHA-512 block sizes";
  const char hash_text7[] = "0ab803344830f92089494fb635ad00d76164ad6e57012b237722df0d7ad26896";
  
  BYTE text8[]="By hashing data that is one byte less than a multiple of a hash block length (like this 127-byte string), bugs may be revealed.";
  const char hash_text8[] = "e4326d0459653d7d3514674d713e74dc3df11ed4d30b4013fd327fdb9e394c26";
  
  BYTE text9[]="The quick brown fox jumps over the lazy dog";
  const char hash_text9[] = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
  
  BYTE text10[]="This test tries to use the n-block utility from the hash library and as a matter of fact we're trying to get only 128 characters";
  const char hash_text10[] = "2ce675bd3b70e104d696d1b25bf3d42b2b45cd776d4f590f210f12c44bf473d5";

  sha256Instance=new Sha256();
  sha256Instance->update(text1, strlen((const char*)text1));
  sha256Instance->final(hash);
  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  Serial.print("Text to hash: ");
  Serial.println("");
  Serial.print("Hash from device: ");
  Serial.println(texthash);
  Serial.print ("Correct hash:     ");
  Serial.println (hash_text1);
  Serial.println("");
  delete sha256Instance;

  sha256Instance=new Sha256();
  sha256Instance->update(text2, strlen((const char*)text2));
  sha256Instance->final(hash);
  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  Serial.print("Text to hash: ");
  Serial.println("abc");
  Serial.print("Hash from device: ");
  Serial.println(texthash);
  Serial.print ("Correct hash:     ");
  Serial.println (hash_text2);
  Serial.println("");
  delete sha256Instance;

  sha256Instance=new Sha256();
  sha256Instance->update(text3, strlen((const char*)text3));
  sha256Instance->final(hash);
  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  Serial.print("Text to hash: ");
  Serial.println("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
  Serial.print("Hash from device: ");
  Serial.println(texthash);
  Serial.print ("Correct hash:     ");
  Serial.println (hash_text3);
  Serial.println("");
  delete sha256Instance;

  sha256Instance=new Sha256();
  sha256Instance->update(text4, strlen((const char*)text4));
  sha256Instance->final(hash);
  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  Serial.print("Text to hash: ");
  Serial.println("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
  Serial.print("Hash from device: ");
  Serial.println(texthash);
  Serial.print ("Correct hash:     ");
  Serial.println (hash_text4);
  Serial.println("");
  delete sha256Instance;

  sha256Instance=new Sha256();
  sha256Instance->update(text5, strlen((const char*)text5));
  sha256Instance->final(hash);
  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  Serial.print("Text to hash: ");
  Serial.println("This is exactly 64 bytes long, not counting the terminating byte");
  Serial.print("Hash from device: ");
  Serial.println(texthash);
  Serial.print ("Correct hash:     ");
  Serial.println (hash_text5);
  Serial.println("");
  delete sha256Instance;

  sha256Instance=new Sha256();
  sha256Instance->update(text6, strlen((const char*)text6));
  sha256Instance->final(hash);
  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  Serial.print("Text to hash: ");
  Serial.println("For this sample, this 63-byte string will be used as input data");
  Serial.print("Hash from device: ");
  Serial.println(texthash);
  Serial.print ("Correct hash:     ");
  Serial.println (hash_text6);
  Serial.println("");
  delete sha256Instance;

  sha256Instance=new Sha256();
  sha256Instance->update(text7, strlen((const char*)text7));
  sha256Instance->final(hash);
  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  Serial.print("Text to hash: ");
  Serial.println("And this textual data, astonishing as it may appear, is exactly 128 bytes in length, as are both SHA-384 and SHA-512 block sizes");
  Serial.print("Hash from device: ");
  Serial.println(texthash);
  Serial.print ("Correct hash:     ");
  Serial.println (hash_text7);
  Serial.println("");
  delete sha256Instance;

  sha256Instance=new Sha256();
  sha256Instance->update(text8, strlen((const char*)text8));
  sha256Instance->final(hash);
  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  Serial.print("Text to hash: ");
  Serial.println("By hashing data that is one byte less than a multiple of a hash block length (like this 127-byte string), bugs may be revealed.");
  Serial.print("Hash from device: ");
  Serial.println(texthash);
  Serial.print ("Correct hash:     ");
  Serial.println (hash_text8);
  Serial.println("");
  delete sha256Instance;

  sha256Instance=new Sha256();
  sha256Instance->update(text9, strlen((const char*)text9));
  sha256Instance->final(hash);
  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  Serial.print("Text to hash: ");
  Serial.println("The quick brown fox jumps over the lazy dog");
  Serial.print("Hash from device: ");
  Serial.println(texthash);
  Serial.print ("Correct hash:     ");
  Serial.println (hash_text9);
  Serial.println("");
  delete sha256Instance;

  sha256Instance=new Sha256();
  sha256Instance->update(text10, strlen((const char*)text10));
  sha256Instance->final(hash);
  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  Serial.print("Text to hash: ");
  Serial.println("This test tries to use the n-block utility from the hash library and as a matter of fact we're trying to get only 128 characters");
  Serial.print("Hash from device: ");
  Serial.println(texthash);
  Serial.print ("Correct hash:     ");
  Serial.println (hash_text10);
  Serial.println("");
  delete sha256Instance;
}

void loop() {
  delay(10);
}
