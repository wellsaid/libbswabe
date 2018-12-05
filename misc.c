#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pbc.h>
#include <mbedtls/aes.h>

#include "bswabe.h"
#include "private.h"

void
bswabe_init_aes( mbedtls_aes_context* ctx, element_t k, int enc, unsigned char* iv )
{
	int key_len;
	unsigned char* key_buf;

	key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
	key_buf = (unsigned char*) malloc(key_len);
	element_to_bytes(key_buf, k);

	if(enc)
		mbedtls_aes_setkey_enc(ctx, key_buf + 1, 128);
	else
		mbedtls_aes_setkey_dec(ctx, key_buf + 1, 128);
	free(key_buf);

	memset(iv, 0, 16);
}

size_t
bswabe_aes_128_cbc_encrypt( char **ct, char* pt, size_t pt_len, element_t k )
{
	unsigned char iv[16];

	mbedtls_aes_context ctx;

	mbedtls_aes_init(&ctx);
	bswabe_init_aes(&ctx, k, 1, iv);

	/* TODO make less crufty */

	/* stuff in real length (big endian) before padding */
	size_t pt_final_len = 4 + pt_len;
	pt_final_len += (16 - ((int) pt_final_len % 16));
	unsigned char *pt_final = calloc(pt_final_len, sizeof(char));
	
	pt_final[0] = (pt_len & 0xff000000)>>24;
	pt_final[1] = (pt_len & 0xff0000)>>16;
	pt_final[2] = (pt_len & 0xff00)>>8;
	pt_final[3] = (pt_len & 0xff)>>0;

	memcpy(pt_final + 4, pt, pt_len);

	*ct = malloc(pt_final_len);
	mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, pt_final_len, iv,
			      (unsigned char*) pt_final,
			      (unsigned char*) *ct);
	
	free(pt_final);
	mbedtls_aes_free(&ctx);
	
	return pt_final_len;
}

size_t
bswabe_aes_128_cbc_decrypt( char** pt, char* ct, size_t ct_len, element_t k )
{
	unsigned char iv[16];
	unsigned int len;

	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	bswabe_init_aes(&ctx, k, 0, iv);

	unsigned char* pt_final = malloc(ct_len);

	if(mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, ct_len, iv,
				 (unsigned char*) ct, (unsigned char*) pt_final) == MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH)
		return 0;

	/* TODO make less crufty */

	/* get real length */
	len = 0;
	len = len
	    | ((pt_final[0])<<24) | ((pt_final[1])<<16)
	    | ((pt_final[2])<<8)  | ((pt_final[3])<<0);
	
	/* truncate any garbage from the padding */
	*pt = malloc(len);
	memcpy(*pt, pt_final + 4, len); 

	free(pt_final);
	return len;

}

void
serialize_uint32( char** b, uint32_t k )
{
        *b = malloc(4);
	
	int i;
	uint8_t byte;

	for( i = 3; i >= 0; i-- )
	{
		byte = (k & 0xff<<(i*8))>>(i*8);
		(*b)[3-i] = byte;
	}
}

uint32_t
unserialize_uint32( char* b, int* offset )
{
	int i;
	uint32_t r;

	r = 0;
	for( i = 3; i >= 0; i-- )
		r |= (b[(*offset)++])<<(i*8);

	return r;
}

size_t
serialize_element( char** b, element_t e )
{
	uint32_t len;

	len = element_length_in_bytes(e);
	*b = malloc(4 + len);

	char *buf1 = NULL;
	serialize_uint32(&buf1, len);
	memcpy(*b, buf1, 4);
	free(buf1);

	unsigned char* buf2 = (unsigned char*) malloc(len);
	element_to_bytes(buf2, e);
	memcpy(*b + 4, buf2, len);
	free(buf2);
	
	return 4+len;
}

void
unserialize_element( char* b, int* offset, element_t e )
{
	uint32_t len;

	len = unserialize_uint32(b, offset);

	unsigned char* buf = malloc(len);
	memcpy(buf, b + *offset, len);
	*offset += len;

	element_from_bytes(e, buf);
	free(buf);
}

size_t
serialize_policy( char** b, bswabe_policy_t* p )
{
	int i;

	char* buf1 = NULL;
	serialize_uint32(&buf1, (uint32_t) p->k);

	char* buf2 = NULL;
	serialize_uint32(&buf2, (uint32_t) p->children_len);
	
	char* buf3 = NULL;
	size_t buf3_len = 0;
	char* buf4 = NULL;
	size_t buf4_len = 0;
	char* buf5 = NULL;
	size_t buf5_len = 0;
	char* buf6[p->children_len];
	size_t buf6_len[p->children_len];
	if( p->children == NULL )
	{
		buf3 = malloc(strlen(p->attr) + 1);
		strcpy(buf3, p->attr);
		buf3_len = strlen(buf3) + 1;

		buf4_len = serialize_element(&buf4, p->c);

		buf5_len = serialize_element(&buf5, p->cp);
	}
	else
	{
		for( i = 0; i < p->children_len; i++ )
		{
			buf6_len[i] = serialize_policy(&buf6[i], &p->children[i]);
		}
	}

	size_t b_len = 8;
	if( p->children == NULL )
	{
		b_len += buf3_len + buf4_len + buf5_len;
	}
	else
	{
		for( i = 0; i < p->children_len; i++ )
		{
			b_len += buf6_len[i];
		}
	}
	*b = malloc(b_len);

	size_t a = 0;
	memcpy(*b, buf1, 4);
	a += 4;
	free(buf1);

	memcpy(*b + a, buf2, 4);
	a += 4;
	free(buf2);

	if( p->children_len == 0 )
	{
		memcpy(*b + a, buf3, buf3_len);
		a += buf3_len;
		free(buf3);

		memcpy(*b + a, buf4, buf4_len);
		a += buf4_len;
		free(buf4);

		memcpy(*b + a, buf5, buf5_len);
		free(buf5);
	}
	else
	{
		for( i = 0; i < p->children_len; i++ )
		{
			memcpy(*b + a, buf6[i], buf6_len[i]);
			a += buf6_len[i];
			free(buf6[i]);			
		}
	}

	return b_len;
}

void
unserialize_policy(  bswabe_policy_t** p, bswabe_pub_t* pub, char* b, int* offset )
{
	int i;

	(*p) = malloc(sizeof(bswabe_policy_t));

	(*p)->k = unserialize_uint32(b, offset);
	(*p)->attr = 0;

	(*p)->children_len = unserialize_uint32(b, offset);
	if( (*p)->children_len == 0 )
	{
		(*p)->children = NULL;
		
		(*p)->attr = malloc(strlen(b + *offset) + 1);
		strcpy((*p)->attr, b + *offset);
		*offset += strlen(b + *offset) + 1;
		
		element_init_G1((*p)->c,  pub->p);
		element_init_G1((*p)->cp, pub->p);

		unserialize_element(b, offset, (*p)->c);
		unserialize_element(b, offset, (*p)->cp);
	}
	else
	{
		(*p)->children = malloc((*p)->children_len*sizeof(bswabe_policy_t));
		bswabe_policy_t* child = NULL;
		for( i = 0; i < (*p)->children_len; i++ )
		{
			unserialize_policy(&child, pub, b, offset);
			memcpy(&(*p)->children[i], child, sizeof(bswabe_policy_t));
		}

		free(child);
	}
}

size_t
bswabe_cph_serialize( char** b, bswabe_cph_t* cph )
{
	char* buf1 = NULL;
	size_t buf1_len = serialize_element(&buf1, cph->cs);

	char* buf2 = NULL;
	size_t buf2_len = serialize_element(&buf2, cph->c);
	
	char* buf3 = NULL;
	size_t buf3_len = serialize_policy(&buf3, cph->p);
	
	size_t b_len = buf1_len + buf2_len + buf3_len; 
	*b = malloc(b_len);

	size_t a = 0;
	memcpy(*b, buf1, buf1_len);
	a+= buf1_len;
	free(buf1);

	memcpy(*b + a, buf2, buf2_len);
	a+= buf2_len;
	free(buf2);

	memcpy(*b + a, buf3, buf3_len);
	free(buf3);

	return b_len;
}

void
bswabe_cph_unserialize( bswabe_cph_t** cph, bswabe_pub_t* pub, char* b, size_t b_len )
{
	int offset;

	*cph = malloc(sizeof(bswabe_cph_t));
	offset = 0;

	element_init_GT((*cph)->cs, pub->p);
	element_init_G1((*cph)->c,  pub->p);

	unserialize_element(b, &offset, (*cph)->cs);
	unserialize_element(b, &offset, (*cph)->c);
	unserialize_policy(&(*cph)->p, pub, b, &offset);
}

void
bswabe_pub_free( bswabe_pub_t* pub )
{
	element_clear(pub->g);
	element_clear(pub->h);
	element_clear(pub->gp);
	element_clear(pub->g_hat_alpha);
	pairing_clear(pub->p);
	free(pub->pairing_desc);
	free(pub);
}

void
bswabe_msk_free( bswabe_msk_t* msk )
{
	element_clear(msk->beta);
	element_clear(msk->g_alpha);
	free(msk);
}

void
bswabe_prv_free( bswabe_prv_t* prv )
{
	int i;
	
	element_clear(prv->d);

	for( i = 0; i < prv->comps_len; i++ )
	{
		bswabe_prv_comp_t* c;

		c = &prv->comps[i];
		free(c->attr);
		element_clear(c->d);
		element_clear(c->dp);
	}

	free(prv->comps);

	free(prv);
}

void
bswabe_policy_free( bswabe_policy_t* p )
{
	int i;

	if( p->children_len == 0 )
	{
		free(p->attr);
		element_clear(p->c);
		element_clear(p->cp);
	}

	for( i = 0; i < p->children_len; i++ )
		bswabe_policy_free(&p->children[i]);

	if(p->children_len > 0)
		free(p->children);

}

void
bswabe_cph_free( bswabe_cph_t* cph )
{
	element_clear(cph->cs);
	element_clear(cph->c);
	bswabe_policy_free(cph->p);
	free(cph->p);
}
