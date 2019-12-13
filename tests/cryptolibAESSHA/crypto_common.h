#ifndef _CRYPTO_COMMON_H_
#define _CRYPTO_COMMON_H_

#define padding_end               free

#define CRYPTO_LITTLE_ENDIAN                  0
#define CRYPTO_BIG_ENDIAN                     1

#define CRYPTO_ARRAY_LENGTH                   8
#define CRYPTO_MAX_PADDING_LENGTH             56
#define CRYPTO_BLOCK_LENGTH                   64

/*
 * padding_start: add padding to hashing array
*  NOTE: requires heap to get memory at runtime
 * Parameters:
 *  [in] *input:    hashing array for padding
 *  [in,out] *input_length: get hashing array length, returns new length
 *  [in] endianess: endianess to use. MD5 little endian, SHA1 and SHA256 use big endian
 * Returns:
 *  new padding array address. NULL if error.
 */
unsigned char *
padding_start(unsigned char *input, unsigned int input_length, unsigned char endianess);

/*
 * compare_arrays: compares 2 arrays
 * Parameters:
 *  [in] *first: 1st array
 *  [in] *second: 2nd array
 *  [in] length: arrays length
 * Returns:
 *  0 if OK otherwise error
 */
unsigned char
compare_arrays(unsigned char *first, unsigned char *second, unsigned length);

#endif
