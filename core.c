#include <stdlib.h>
#include <string.h>
#ifndef BSWABE_DEBUG
#define NDEBUG
#endif
#include <assert.h>

#if defined(CONTIKI_TARGET_ZOUL)
#include <dev/sha256.h>
#else
#include <mbedtls/sha1.h>
#endif

#include <pbc.h>

#include "bswabe.h"
#include "private.h"

#define TYPE_A_PARAMS \
"type a\n" \
"q 25592495515765067051642300423336670621430538560550086238294375266242321140927190193065045904197241858828084036025639\n" \
"h 35022192055157566125252273151275491786431099978820680852024212634920\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"

char last_error[256];

char*
bswabe_error()
{
	return last_error;
}

void
raise_error(char* fmt, ...)
{
	va_list args;

#ifdef BSWABE_DEBUG
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(1);
#else
	va_start(args, fmt);
	vsnprintf(last_error, 256, fmt, args);
	va_end(args);
#endif
}

void
element_from_string( element_t h, char* s )
{
#if defined(CONTIKI_TARGET_ZOUL)
    uint8_t ret;
    crypto_init();

    sha256_state_t state;
    if( (ret = sha256_init(&state)) != CRYPTO_SUCCESS ){
    	printf("ERROR: initializing sha256 structure (error: %u)", ret);
    	exit(1);
    }

    if( (ret = sha256_process(&state, s, strlen(s))) != CRYPTO_SUCCESS){
    	printf("ERROR: performing sha256 operation (error: %u)", ret);
    	exit(1);
    }

    unsigned char r[32];
    if( (ret = sha256_done(&state, &r[0])) != CRYPTO_SUCCESS){
    	printf("ERROR: getting result of sha256 operation (error: %u)", ret);
    	exit(1);
    }

    crypto_disable();
    element_from_hash(h, r, 32);
#else
    unsigned char r[20];
    mbedtls_sha1_ret((unsigned char*) s, strlen(s), r);
    element_from_hash(h, r, 20);
#endif
}

int
bswabe_setup( bswabe_pub_t** pub, bswabe_msk_t** msk )
{
	element_t alpha;
	
	/* initialize */
	*pub = heapmem_alloc(sizeof(bswabe_pub_t));
	*msk = heapmem_alloc(sizeof(bswabe_msk_t));

	(*pub)->pairing_desc = strdup(TYPE_A_PARAMS);
	if( pairing_init_set_buf((*pub)->p, (*pub)->pairing_desc, strlen((*pub)->pairing_desc)) ){
		return 0;
	}

	element_init_G1((*pub)->g,           (*pub)->p);
	element_init_G1((*pub)->h,           (*pub)->p);
	element_init_G2((*pub)->gp,          (*pub)->p);
	element_init_GT((*pub)->g_hat_alpha, (*pub)->p);
	element_init_Zr(alpha,               (*pub)->p);
	element_init_Zr((*msk)->beta,        (*pub)->p);
	element_init_G2((*msk)->g_alpha,     (*pub)->p);

	/* compute */

 	element_random(alpha);
 	element_random((*msk)->beta);
	element_random((*pub)->g);
	element_random((*pub)->gp);

	element_pow_zn((*msk)->g_alpha, (*pub)->gp, alpha);
	element_pow_zn((*pub)->h, (*pub)->g, (*msk)->beta);
       pairing_apply((*pub)->g_hat_alpha, (*pub)->g, (*msk)->g_alpha, (*pub)->p);

       return 1;
}

void bswabe_keygen( bswabe_prv_t** prv, bswabe_pub_t* pub, bswabe_msk_t* msk, char** attributes, size_t num_attributes)
{
	size_t i;
	
	element_t g_r;
	element_t r;
	element_t beta_inv;

	/* initialize */

	(*prv) = heapmem_alloc(sizeof(bswabe_prv_t));

	element_init_G2((*prv)->d, pub->p);
	element_init_G2(g_r, pub->p);
	element_init_Zr(r, pub->p);
	element_init_Zr(beta_inv, pub->p);

	(*prv)->comps = heapmem_alloc(num_attributes*sizeof(bswabe_prv_comp_t));
	(*prv)->comps_len = 0;
	
	/* compute */
 	element_random(r);
	element_pow_zn(g_r, pub->gp, r);

	element_mul((*prv)->d, msk->g_alpha, g_r);
	element_invert(beta_inv, msk->beta);
	element_pow_zn((*prv)->d, (*prv)->d, beta_inv);

	for( i = 0; i < num_attributes; i++ )
	{
		bswabe_prv_comp_t c;
		element_t h_rp;
		element_t rp;

		c.attr = strdup(attributes[i]);

		element_init_G2(c.d,  pub->p);
		element_init_G1(c.dp, pub->p);
		element_init_G2(h_rp, pub->p);
		element_init_Zr(rp,   pub->p);
		
 		element_from_string(h_rp, c.attr);
 		element_random(rp);

		element_pow_zn(h_rp, h_rp, rp);

		element_mul(c.d, g_r, h_rp);
		element_pow_zn(c.dp, pub->g, rp);

		element_clear(h_rp);
		element_clear(rp);

		memcpy(&(*prv)->comps[i], &c, sizeof(bswabe_prv_comp_t));
		(*prv)->comps_len++;
	}
}

void
base_node( bswabe_policy_t** p, int k, char* s )
{
	(*p) = heapmem_alloc(sizeof(bswabe_policy_t));
	(*p)->k = k;
	(*p)->attr = s? strdup(s) : NULL;
	(*p)->children = NULL;
	(*p)->children_len = 0;
	(*p)->q = 0;
}

/* Helper method:
 *     Counts the number of tokens in the string
 */
size_t
strtok_count( char* s,  const char* delim )
{
	int count = 0;
	char *ptr = s;
	while((ptr = strpbrk(ptr, delim)) != NULL)
	{
		count++;
		ptr++;
	}

	return count;
}

/*
	TODO convert this to use a GScanner and handle quotes and / or
	escapes to allow attributes with whitespace or = signs in them
*/
int
parse_policy_postfix( bswabe_policy_t** root, char* s )
{
	int i;
	
	char*  tok;
	bswabe_policy_t* stack; /* pointers to bswabe_policy_t's */
	size_t stack_len = 0;
	bswabe_policy_t* top;
	
	stack    = heapmem_alloc((strtok_count(s, " ")+1)*sizeof(bswabe_policy_t));
	top = stack;

	char* s_tmp = strdup(s);

	tok = strtok(s_tmp, " ");
	while( tok )
	{
		int k, n;
		bswabe_policy_t* node;

		if( sscanf(tok, "%dof%d", &k, &n) != 2 )
		{
			/* push leaf token */
			base_node(&node, 1, tok);
			memcpy(top++, node, sizeof(bswabe_policy_t));
			stack_len++;
		}
		else
		{
			/* parse "kofn" operator */
			if( k < 1 )
			{
				raise_error("error parsing \"%s\": trivially satisfied operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( k > n )
			{
				raise_error("error parsing \"%s\": unsatisfiable operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( n == 1 )
			{
				raise_error("error parsing \"%s\": identity operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( n > stack_len )
			{
				raise_error("error parsing \"%s\": stack underflow at \"%s\"\n", s, tok);
				return 0;
			}
			
			/* pop n things and fill in children */
			base_node(&node, k, 0);
			node->children = heapmem_alloc(n*sizeof(bswabe_policy_t));
			node->children_len = 0;
			for( i = n - 1; i >= 0; i-- )
			{
				memcpy(&node->children[i], --top, sizeof(bswabe_policy_t));
				stack_len--;
				node->children_len++;
			}
			
			/* push result */
			memcpy(top++, node, sizeof(bswabe_policy_t));
			stack_len++;
		}

		heapmem_free(node);
		tok = strtok(NULL, " ");
	}

	if( stack_len > 1 )
	{
		raise_error("error parsing \"%s\": extra tokens left on stack\n", s);
		return 0;
	}
	else if( stack_len < 1 )
	{
		raise_error("error parsing \"%s\": empty policy\n", s);
		return 0;
	}

	*root = heapmem_alloc(sizeof(bswabe_policy_t));
	memcpy(*root, --top, sizeof(bswabe_policy_t));

	heapmem_free(stack);
	heapmem_free(s_tmp);
	
	return 1;
}

void
rand_poly( bswabe_polynomial_t** q, int deg, element_t zero_val )
{
	int i;

	(*q) = heapmem_alloc(sizeof(bswabe_polynomial_t));
	(*q)->deg = deg;
	(*q)->coef = heapmem_alloc((deg + 1)*sizeof(element_t));

	for( i = 0; i < (*q)->deg + 1; i++ )
		element_init_same_as((*q)->coef[i], zero_val);

	element_set((*q)->coef[0], zero_val);

	for( i = 1; i < (*q)->deg + 1; i++ )
 		element_random((*q)->coef[i]);
}

void
eval_poly( element_t r, bswabe_polynomial_t* q, element_t x )
{
	int i;
	element_t s, t;

	element_init_same_as(s, r);
	element_init_same_as(t, r);

	element_set0(r);
	element_set1(t);

	for( i = 0; i < q->deg + 1; i++ )
	{
		/* r += q->coef[i] * t */
		element_mul(s, q->coef[i], t);
		element_add(r, r, s);

		/* t *= x */
		element_mul(t, t, x);
	}

	element_clear(s);
	element_clear(t);
}

size_t count_policy_attributes(bswabe_policy_t* p)
{
	int i;
	size_t toret = 0;

	if( p->children == NULL ){
		return 1;
	}
	else
		for( i = 0; i < p->children_len; i++ ){
			toret += count_policy_attributes(&p->children[i]);
		}

	return toret;
}

void
pre_fill_policy( element_t** h_vec, size_t* a, bswabe_policy_t* p, bswabe_pub_t* pub )
{
	int i;
	
	if(*h_vec == NULL)
	{
		size_t num = count_policy_attributes(p);
		*h_vec = heapmem_alloc(num*sizeof(element_t));
	}

	if( p->children == NULL )
	{
		element_t* h = *h_vec + *a;
		element_init_G2(*h, pub->p);
		element_from_string(*h, p->attr);
		*a += 1;
	}
	else
		for( i = 0; i < p->children_len; i++ )
			pre_fill_policy(h_vec, a, &p->children[i], pub);
}

void
fill_policy( bswabe_policy_t* p, bswabe_pub_t* pub, element_t e, element_t** h_vec )
{
	int i;
	element_t r;
	element_t t;
	element_t* h = NULL;

	element_init_Zr(r, pub->p);
	element_init_Zr(t, pub->p);

	if(h_vec == NULL)
	{		
		h = heapmem_alloc(sizeof(element_t));
		element_init_G2(*h, pub->p);
	}

	rand_poly(&p->q, p->k - 1, e);

	if( p->children == NULL )
	{
		element_init_G1(p->c,  pub->p);
		element_init_G2(p->cp, pub->p);

		if(h_vec == NULL)
			element_from_string(*h, p->attr);
		else
			h = (*h_vec)++;

		element_pow_zn(p->c,  pub->g, p->q->coef[0]);
		element_pow_zn(p->cp, *h, p->q->coef[0]);
	}
	else
		for( i = 0; i < p->children_len; i++ )
		{
			element_set_si(r, i + 1);    
			eval_poly(t, p->q, r);

			fill_policy(&p->children[i], pub, t, h_vec);
		}

	element_clear(r);
	element_clear(t);
	if(h_vec == NULL)
	{
		element_clear(*h);
		heapmem_free(h);
	}
}

size_t
bswabe_enc_byte_array( char** ct, bswabe_cph_t* cph, bswabe_pub_t* pub, char*  m, size_t m_len, element_t m_e )
{
	int i;
	uint8_t byte;

	/* rest of the encryption from http://hms.isi.jhu.edu/acsc/cpabe/cpabe-0.11.tar.gz */
	char* cph_buf = NULL;
	size_t cph_buf_len = bswabe_cph_serialize(&cph_buf, cph);
	bswabe_cph_free(cph);

	char* aes_buf = NULL;
	size_t aes_buf_len = bswabe_aes_128_cbc_encrypt(&aes_buf, m, m_len, m_e);
	element_clear(m_e);
	
	size_t ct_len = 12 + aes_buf_len + cph_buf_len;
	*ct = heapmem_alloc(ct_len);

	size_t a = 0;

	/* write plaintext len as 32-bit big endian int */
	for( i = 3; i >= 0; i-- )
	{
		byte = (m_len & 0xff<<(i*8))>>(i*8);
		(*ct)[a] = byte;
		a++;
	}

	/* write aes_buf */
	for( i = 3; i >= 0; i-- ){
		byte = (aes_buf_len & 0xff<<(i*8))>>(i*8);
		(*ct)[a] = byte;
		a++;
	}
	memcpy(*ct + a, aes_buf, aes_buf_len);
	a += aes_buf_len;

	/* write cph_buf */
	for( i = 3; i >= 0; i-- ){
		byte = (cph_buf_len & 0xff<<(i*8))>>(i*8);
		(*ct)[a] = byte;
		a++;
	}
	memcpy(*ct + a, cph_buf, cph_buf_len);

	heapmem_free(cph_buf);
	heapmem_free(aes_buf);
	
	return ct_len;
}
	
bswabe_cph_t*
bswabe_enc( bswabe_pub_t* pub, element_t m_e,  element_t s, char* policy)
{
	bswabe_cph_t* cph;

	/* initialize */
	cph = heapmem_alloc(sizeof(bswabe_cph_t));

	element_init_Zr(s, pub->p);
	element_init_GT(m_e, pub->p);
	element_init_GT(cph->cs, pub->p);
	element_init_G1(cph->c,  pub->p);
	parse_policy_postfix(&cph->p, policy);
	
	/* compute */
 	element_random(m_e);
 	element_random(s);
	element_pow_zn(cph->cs, pub->g_hat_alpha, s);
	element_mul(cph->cs, cph->cs, m_e);

	element_pow_zn(cph->c, pub->h, s);
	
	return cph;
}

void
check_sat( bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, l;

	p->satisfiable = 0;
	if( p->children_len == 0 )
	{
		for( i = 0; i < prv->comps_len; i++ )
			if( !strcmp(prv->comps[i].attr, p->attr) )
			{
				p->satisfiable = 1;
				p->attri = i;
				break;
			}
	}
	else
	{
		for( i = 0; i < p->children_len; i++ )
			check_sat(&p->children[i], prv);

		l = 0;
		for( i = 0; i < p->children_len; i++ )
			if( p->children[i].satisfiable )
				l++;

		if( l >= p->k )
			p->satisfiable = 1;
	}
}

void
pick_sat_naive( bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, k, l = 0;

	assert(p->satisfiable == 1);

	if( p->children_len == 0 )
		return;

	p->satl_len = 0;
	for( i = 0; i < p->children_len && l < p->k; i++ )
		if( p->children[i].satisfiable )
		{
			l++;
			p->satl++;
		}
	
	l = 0;
	p->satl = heapmem_alloc(p->satl_len*sizeof(int));
	p->satl_len = 0;
	for( i = 0; i < p->children_len && l < p->k; i++ )
		if( p->children[i].satisfiable )
		{
			pick_sat_naive(&p->children[i], prv);
			l++;
			k = i + 1;
			p->satl[p->satl_len++] = k;
		}
}

/* TODO there should be a better way of doing this */
bswabe_policy_t* cur_comp_pol;
int
cmp_int( const void* a, const void* b )
{
	int k, l;
	
	k = cur_comp_pol->children[*((int*)a)].min_leaves;
	l = cur_comp_pol->children[*((int*)b)].min_leaves;

	return
		k <  l ? -1 :
		k == l ?  0 : 1;
}

void
pick_sat_min_leaves( bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, k, l = 0;
	int* c;

	assert(p->satisfiable == 1);

	if( p->children_len == 0 )
		p->min_leaves = 1;
	else
	{
		for( i = 0; i < p->children_len; i++ )
			if( p->children[i].satisfiable )
				pick_sat_min_leaves(&p->children[i], prv);

		c = heapmem_alloc(sizeof(int)*p->children_len);
		for( i = 0; i < p->children_len; i++ )
			c[i] = i;

		cur_comp_pol = p;
		qsort(c, p->children_len, sizeof(int), cmp_int);

		/* count how many satl we need */
		p->satl_len = 0;
		for( i = 0; i < p->children_len && l < p->k; i++ )
			if( p->children[c[i]].satisfiable )
			{
				l++;
				p->satl_len ++;
			}
		
		p->satl = heapmem_alloc(p->satl_len*sizeof(int));
		p->satl_len = 0;
		p->min_leaves = 0;
		l = 0;

		for( i = 0; i < p->children_len && l < p->k; i++ )
			if( p->children[c[i]].satisfiable )
			{
				l++;
				p->min_leaves += p->children[c[i]].min_leaves;
				k = c[i] + 1;
				p->satl[p->satl_len++] = k;
			}
		assert(l == p->k);

		heapmem_free(c);
	}
}

void
lagrange_coef( element_t r, int* s, size_t s_len, int i )
{
	int j, k;
	element_t t;

	element_init_same_as(t, r);

	element_set1(r);
	for( k = 0; k < s_len; k++ )
	{
		j = s[k];
		if( j == i )
			continue;
		element_set_si(t, - j);
		element_mul(r, r, t); /* num_muls++; */
		element_set_si(t, i - j);
		element_invert(t, t);
		element_mul(r, r, t); /* num_muls++; */
	}

	element_clear(t);
}

void
dec_leaf_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	bswabe_prv_comp_t* c;
	element_t s;

	c = &prv->comps[p->attri];

	element_init_GT(s, pub->p);

	pairing_apply(r, p->c,  c->d,  pub->p); /* num_pairings++; */
	pairing_apply(s, p->cp, c->dp, pub->p); /* num_pairings++; */
	element_invert(s, s);
	element_mul(r, r, s); /* num_muls++; */

	element_clear(s);
}

void dec_node_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t s;
	element_t t;

	element_init_GT(s, pub->p);
	element_init_Zr(t, pub->p);

	element_set1(r);
	for( i = 0; i < p->satl_len; i++ )
	{
		dec_node_naive(s, &p->children[p->satl[i] - 1], prv, pub);
 		lagrange_coef(t, p->satl, p->satl_len, p->satl[i]);
		element_pow_zn(s, s, t); /* num_exps++; */
		element_mul(r, r, s); /* num_muls++; */
	}

	element_clear(s);
	element_clear(t);
}

void
dec_node_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children_len == 0 )
		dec_leaf_naive(r, p, prv, pub);
	else
		dec_internal_naive(r, p, prv, pub);
}

void
dec_naive( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	dec_node_naive(r, p, prv, pub);
}

void
dec_leaf_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	bswabe_prv_comp_t* c;
	element_t s;

	c = &prv->comps[p->attri];

	if( !c->used )
	{
		c->used = 1;
		element_init_G1(c->z,  pub->p);
		element_init_G1(c->zp, pub->p);
		element_set1(c->z);
		element_set1(c->zp);
	}

	element_init_G1(s, pub->p);

	element_pow_zn(s, p->c, exp); /* num_exps++; */
	element_mul(c->z, c->z, s); /* num_muls++; */

	element_pow_zn(s, p->cp, exp); /* num_exps++; */
	element_mul(c->zp, c->zp, s); /* num_muls++; */

	element_clear(s);
}

void dec_node_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t t;
	element_t expnew;

	element_init_Zr(t, pub->p);
	element_init_Zr(expnew, pub->p);

	for( i = 0; i < p->satl_len; i++ )
	{
 		lagrange_coef(t, p->satl, p->satl_len, p->satl[i]);
		element_mul(expnew, exp, t); /* num_muls++; */
		dec_node_merge(expnew, &p->children[p->satl[i]- 1], prv, pub);
	}

	element_clear(t);
	element_clear(expnew);
}

void
dec_node_merge( element_t exp, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children_len == 0 )
		dec_leaf_merge(exp, p, prv, pub);
	else
		dec_internal_merge(exp, p, prv, pub);
}

void
dec_merge( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t one;
	element_t s;

	/* first mark all attributes as unused */
	for( i = 0; i < prv->comps_len; i++ )
		prv->comps[i].used = 0;

	/* now fill in the z's and zp's */
	element_init_Zr(one, pub->p);
	element_set1(one);
	dec_node_merge(one, p, prv, pub);
	element_clear(one);

	/* now do all the pairings and multiply everything together */
	element_set1(r);
	element_init_GT(s, pub->p);
	for( i = 0; i < prv->comps_len; i++ )
		if( prv->comps[i].used )
		{
			bswabe_prv_comp_t* c = &prv->comps[i];

			pairing_apply(s, c->z, c->d, pub->p); /* num_pairings++; */
			element_mul(r, r, s); /* num_muls++; */

			pairing_apply(s, c->zp, c->dp, pub->p); /* num_pairings++; */
			element_invert(s, s);
			element_mul(r, r, s); /* num_muls++; */
		}
	element_clear(s);
}

void
dec_leaf_flatten( element_t r, element_t exp,
									bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	bswabe_prv_comp_t* c;
	element_t s;
	element_t t;

	c = &prv->comps[p->attri];

	element_init_GT(s, pub->p);
	element_init_GT(t, pub->p);

	pairing_apply(s, p->c,  c->d,  pub->p); /* num_pairings++; */
	pairing_apply(t, p->cp, c->dp, pub->p); /* num_pairings++; */
	element_invert(t, t);
	element_mul(s, s, t); /* num_muls++; */
	element_pow_zn(s, s, exp); /* num_exps++; */

	element_mul(r, r, s); /* num_muls++; */

	element_clear(s);
	element_clear(t);
}

void dec_node_flatten( element_t r, element_t exp,
											 bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_flatten( element_t r, element_t exp,
											bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t t;
	element_t expnew;

	element_init_Zr(t, pub->p);
	element_init_Zr(expnew, pub->p);

	for( i = 0; i < p->satl_len; i++ )
	{
 		lagrange_coef(t, p->satl, p->satl_len, p->satl[i]);
		element_mul(expnew, exp, t); /* num_muls++; */
		dec_node_flatten(r, expnew, &p->children[p->satl[i] - 1], prv, pub);
	}

	element_clear(t);
	element_clear(expnew);
}

void
dec_node_flatten( element_t r, element_t exp,
									bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children_len == 0 )
		dec_leaf_flatten(r, exp, p, prv, pub);
	else
		dec_internal_flatten(r, exp, p, prv, pub);
}

void
dec_flatten( element_t r, bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	element_t one;

	element_init_Zr(one, pub->p);

	element_set1(one);
	element_set1(r);

	dec_node_flatten(r, one, p, prv, pub);

	element_clear(one);
}

size_t
bswabe_dec_byte_array( char **m, bswabe_pub_t* pub, bswabe_prv_t* prv,  char * c, size_t c_len )
{
	int i;
	
	/* operations before decryption from: http://hms.isi.jhu.edu/acsc/cpabe/cpabe-0.11.tar.gz  */
	size_t a = 0;
	
	/* read plaintext len as 32-bit big endian int */
	size_t m_len = 0;
	for( i = 3; i >= 0; i-- )
	{
		m_len |= c[a]<<(i*8);
		a++;
	}

	/* read aes buf */
	size_t aes_buf_len = 0;
	for( i = 3; i >= 0; i-- )
	{
		aes_buf_len |= c[a]<<(i*8);
		a++;
	}
	char *aes_buf = heapmem_alloc(aes_buf_len);
	memcpy(aes_buf, c + a, aes_buf_len);
	a += aes_buf_len;
    
	/* read cph buf */
	size_t cph_buf_len = 0;
	for( i = 3; i >= 0; i-- )
	{
		cph_buf_len |= c[a]<<(i*8);
		a++;
	}
	char* cph_buf = heapmem_alloc(cph_buf_len);
	memcpy(cph_buf, c + a, cph_buf_len);	

	element_t m_e;
	bswabe_cph_t* cph = NULL;
	bswabe_cph_unserialize(&cph, pub, cph_buf, cph_buf_len);
	bswabe_dec(pub, prv, cph, m_e);

	m_len = bswabe_aes_128_cbc_decrypt(m, aes_buf, aes_buf_len, m_e);

	heapmem_free(aes_buf);
	heapmem_free(cph_buf);

	return m_len;
}
	
int bswabe_dec( bswabe_pub_t* pub, bswabe_prv_t* prv, bswabe_cph_t* cph, element_t m_e )
{
	element_t t;
	element_init_GT(m_e, pub->p);
	element_init_GT(t, pub->p);

	check_sat(cph->p, prv);
	if( !cph->p->satisfiable )
	{
		return 0;
	}

/* 	if( no_opt_sat ) */
/* 		pick_sat_naive(cph->p, prv); */
/* 	else */
	pick_sat_min_leaves(cph->p, prv);

/* 	if( dec_strategy == DEC_NAIVE ) */
/* 		dec_naive(t, cph->p, prv, pub); */
/* 	else if( dec_strategy == DEC_FLATTEN ) */
	dec_flatten(t, cph->p, prv, pub);
/* 	else */
/* 		dec_merge(t, cph->p, prv, pub); */

	element_mul(m_e, cph->cs, t); /* num_muls++; */

	pairing_apply(t, cph->c, prv->d, pub->p); /* num_pairings++; */
	element_invert(t, t);
	element_mul(m_e, m_e, t); /* num_muls++; */

	return 1;
}
