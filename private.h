/*
	Include pbc.h, mbedtls/aes.h and bswabe.h before including this file.
*/

struct bswabe_pub_s
{
	char* pairing_desc;
	pairing_t p;
	element_t g;           /* G_1 */
	element_t h;           /* G_1 */
	element_t gp;          /* G_2 */
	element_t g_hat_alpha; /* G_T */
};

struct bswabe_msk_s
{
	element_t beta;    /* Z_r */
	element_t g_alpha; /* G_2 */
};

typedef struct
{
	/* these actually get serialized */
	char* attr;
	element_t d;  /* G_2 */
	element_t dp; /* G_2 */

	/* only used during dec (only by dec_merge) */
	int used;
	element_t z;  /* G_1 */
	element_t zp; /* G_1 */
}
bswabe_prv_comp_t;

struct bswabe_prv_s
{
	element_t d;   /* G_2 */
	bswabe_prv_comp_t* comps; /* bswabe_prv_comp_t's */
	size_t comps_len;
};

typedef struct
{
	int deg;
	/* coefficients from [0] x^0 to [deg] x^deg */
	element_t* coef; /* G_T (of length deg + 1) */
}
bswabe_polynomial_t;


typedef struct bswabe_policy_t bswabe_policy_t;

struct bswabe_policy_t
{
	/* serialized */
	int k;            /* one if leaf, otherwise threshold */
	char* attr;       /* attribute string if leaf, otherwise null */
	element_t c;      /* G_1, only for leaves */
	element_t cp;     /* G_1, only for leaves */
	bswabe_policy_t* children; /* pointers to bswabe_policy_t's, len == 0 for leaves */
	size_t children_len;

	/* only used during encryption */
	bswabe_polynomial_t* q;

	/* only used during decryption */
	int satisfiable;
	int min_leaves;
	int attri;
	int* satl;
	size_t satl_len;
};

struct bswabe_cph_s
{
	element_t cs; /* G_T */
	element_t c;  /* G_1 */
	bswabe_policy_t* p;
};

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
void bswabe_init_aes( mbedtls_aes_context* ctx, element_t k, unsigned char* iv );

/*
  Again, exactly what it seems.
*/
void bswabe_policy_free( bswabe_policy_t* p );
