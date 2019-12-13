
#include "crypto_common.h"

unsigned char parityBits[128] =
{
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0
};

/*
 * padding_start: add padding to hashing array
*  NOTE: requires heap to get memory at runtime
 * Parameters:
 *  [in] *input:    hashing array for padding
 *  [in,out] input_length: get hashing array length, returns new length
 *  [in] endianess: endianess to use. MD5 little endian, SHA1 and SHA256 use big endian
 * Returns:
 *  new padding array address. NULL if error.
 */
unsigned char *
padding_start(unsigned char *input, unsigned int input_length, unsigned char endianess)
{
  
  unsigned char *padding_array;
  signed char padding_length;
  unsigned int temp_length;
  unsigned int bits_length;
  unsigned int final_length;
  
  temp_length = input_length % CRYPTO_BLOCK_LENGTH;
  
  /*get padding length: padding special case when 448 mod 512*/
  /*working with bytes rather than bits*/
  if( !((padding_length = CRYPTO_MAX_PADDING_LENGTH-(temp_length%CRYPTO_BLOCK_LENGTH)) > 0) )
     padding_length = CRYPTO_BLOCK_LENGTH - (temp_length%CRYPTO_MAX_PADDING_LENGTH);
  
  padding_length +=  temp_length/CRYPTO_BLOCK_LENGTH;
  temp_length = input_length;
  
  /*reserve necessary memory*/
  final_length = temp_length + padding_length + CRYPTO_ARRAY_LENGTH/*bits length*/;
  /*if( (padding_array = (unsigned char *)malloc(final_length)) == NULL )
     return (unsigned char *)NULL;not enough mem*/
  
  /*copy original data to new padding array*/
  memcpy((void*)padding_array,(void*)input,temp_length);
  
  /*add padding*/
  padding_array[temp_length++] = 0x80;/*first bit enabled*/
  while((--padding_length != 0))
    padding_array[temp_length++] = 0;/*clear the rest*/
  
  /*add length depending on endianess: get number of bits*/
  bits_length = input_length << 3;
  input_length = final_length;
  
  if( endianess == CRYPTO_LITTLE_ENDIAN )
  {
    padding_array[temp_length++] = bits_length     & 0xff;
    padding_array[temp_length++] = bits_length>>8  & 0xff;
    padding_array[temp_length++] = bits_length>>16 & 0xff;
    padding_array[temp_length++] = bits_length>>24 & 0xff;
    padding_array[temp_length++] = 0;
    padding_array[temp_length++] = 0;
    padding_array[temp_length++] = 0;
    padding_array[temp_length  ] = 0;
  }
  else/*CRYPTO_BIG_ENDIAN*/
  {
    padding_array[temp_length++] = 0; 
    padding_array[temp_length++] = 0; 
    padding_array[temp_length++] = 0; 
    padding_array[temp_length++] = 0; 
    padding_array[temp_length++] = bits_length>>24 & 0xff;
    padding_array[temp_length++] = bits_length>>16 & 0xff;
    padding_array[temp_length++] = bits_length>>8  & 0xff;
    padding_array[temp_length  ] = bits_length     & 0xff;
  }
  
  return padding_array;
}
