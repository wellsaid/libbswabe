/*
  Include glib.h and pbc.h before including this file. Note that this
  file should be included at most once.
*/

#if defined (__cplusplus)
extern "C" {
#endif
	
/*
  A public key.
*/
typedef struct bswabe_pub_s bswabe_pub_t;

struct bswabe_pub_s
{
	char* pairing_desc;
	pairing_t p;
	element_t g;           /* G_1 */
	element_t h;           /* G_1 */
	element_t gp;          /* G_2 */
	element_t g_hat_alpha; /* G_T */
};
	
/*
  A master secret key.
*/
typedef struct bswabe_msk_s bswabe_msk_t;

struct bswabe_msk_s
{
	element_t beta;    /* Z_r */
	element_t g_alpha; /* G_2 */
};
	
/*
  A private key.
*/
typedef struct bswabe_prv_s bswabe_prv_t;

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
	
typedef struct bswabe_policy_t bswabe_policy_t;

typedef struct
{
	int deg;
	/* coefficients from [0] x^0 to [deg] x^deg */
	element_t* coef; /* G_T (of length deg + 1) */
}
bswabe_polynomial_t;
	
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

/*
  A ciphertext. Note that this library only handles encrypting a
  single group element, so if you want to encrypt something bigger,
  you will have to use that group element as a symmetric key for
  hybrid encryption (which you do yourself).
*/
typedef struct bswabe_cph_s bswabe_cph_t;

struct bswabe_cph_s
{
	element_t cs; /* G_T */
	element_t c;  /* G_1 */
	bswabe_policy_t* p;
};
	
/*
  Generate a public key and corresponding master secret key, and
  assign the *pub and *msk pointers to them. The space used may be
  later freed by calling bswabe_pub_free(*pub) and
  bswabe_msk_free(*msk).
*/
int bswabe_setup( bswabe_pub_t** pub, bswabe_msk_t** msk );

/*
  Generate a private key with the given set of attributes. The final
  argument should be a null terminated array of pointers to strings,
  one for each attribute.
*/
void bswabe_keygen( bswabe_prv_t** prv,  bswabe_pub_t* pub,
		    bswabe_msk_t* msk,
		    char** attributes, size_t num_attributes );

/*
  Pick a random group element and encrypt it under the specified
  access policy. The resulting ciphertext is returned and the
  element_t given as an argument (which need not be initialized) is
  set to the random group element.

  After using this function, it is normal to extract the random data
  in m using the pbc functions element_length_in_bytes and
  element_to_bytes and use it as a key for hybrid encryption.

  The policy is specified as a simple string which encodes a postorder
  traversal of threshold tree defining the access policy. As an
  example,

    "foo bar fim 2of3 baf 1of2"

  specifies a policy with two threshold gates and four leaves. It is
  not possible to specify an attribute with whitespace in it (although
  "_" is allowed).

  Numerical attributes and any other fancy stuff are not supported.

  Returns null if an error occured, in which case a description can be
  retrieved by calling bswabe_error().
*/
bswabe_cph_t* bswabe_enc( bswabe_pub_t* pub, element_t m_e,  element_t s, char* policy);
size_t bswabe_enc_byte_array( char** ct, bswabe_cph_t* cph, bswabe_pub_t* pub, char*  m, size_t m_len, element_t m_e );
void pre_fill_policy( element_t** h_vec, size_t* a, bswabe_policy_t* p, bswabe_pub_t* pub );
void fill_policy( bswabe_policy_t* p, bswabe_pub_t* pub, element_t e, element_t** h_vec );
	
/*
  Decrypt the specified ciphertext using the given private key,
  filling in the provided element m (which need not be initialized)
  with the result.

  Returns true if decryption succeeded, false if this key does not
  satisfy the policy of the ciphertext (in which case m is unaltered).
*/
size_t bswabe_dec_byte_array( char **m, bswabe_pub_t* pub, bswabe_prv_t* prv,  char * c, size_t c_len);
int bswabe_dec( bswabe_pub_t* pub, bswabe_prv_t* prv, bswabe_cph_t* cph, element_t m );
	
/*
  Again, exactly what it seems.
*/
void bswabe_pub_free( bswabe_pub_t* pub );
void bswabe_msk_free( bswabe_msk_t* msk );
void bswabe_prv_free( bswabe_prv_t* prv );
void bswabe_cph_free( bswabe_cph_t* cph );

/*
  Return a description of the last error that occured. Call this after
  bswabe_enc or bswabe_dec returns 0. The returned string does not
  need to be free'd.
*/
char* bswabe_error();
	
#if defined (__cplusplus)
} // extern "C"
#endif
