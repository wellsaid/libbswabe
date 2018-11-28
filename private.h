/*
	Include pbc.h, mbedtls/aes.h and bswabe.h before including this file.
*/

/*
  Exactly what it seems.
*/
size_t bswabe_cph_serialize( char** b, bswabe_cph_t* cph );

/*
  Also exactly what it seems. If free is true, the GByteArray passed
  in will be free'd after it is read.
*/
void bswabe_cph_unserialize( bswabe_cph_t** cph, bswabe_pub_t* pub, char* b, size_t b_len );

/*
 * AES CBC Encryption/Decryption functions
*/
size_t bswabe_aes_128_cbc_encrypt( char** ct, char* pt, size_t pt_len, element_t k );
size_t bswabe_aes_128_cbc_decrypt( char** pt, char* ct, size_t ct_len, element_t k );
void bswabe_init_aes( mbedtls_aes_context* ctx, element_t k, int enc, unsigned char* iv );

/*
  Again, exactly what it seems.
*/
void bswabe_policy_free( bswabe_policy_t* p );
