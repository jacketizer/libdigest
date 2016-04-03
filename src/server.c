#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "parse.h"
#include "hash.h"
#include "client.h"

int
digest_server_parse(digest_t *digest, const char *digest_string)
{
	digest_s *dig = (digest_s *) digest;

	return parse_digest(dig, digest_string);
}

int
digest_server_generate_nonce(digest_t *digest)
{
	//digest_s *dig = (digest_s *) digest;

	/* Use srand and base64 or md5.
	   Do the same with cnonce and opaque.
	   How should the strings be allocated and free'd? */

	return 0;
}

/**
 * Generates the WWW-Authenticate header string.
 *
 * Attributes that must be set manually before calling this function:
 *
 *  - Realm
 *  - Algorithm
 *  - Nonce
 *
 * If not set, NULL will be returned.
 *
 * Returns the number of bytes in the result string.
 */
size_t
digest_server_generate_header(digest_t *digest, char *result, size_t max_length)
{
	digest_s *dig = (digest_s *) digest;
	char *qop_value, *algorithm_value;
	size_t result_size; /* The size of the result string */
	int sz;

	/* Check length of char attributes to prevent buffer overflow */
	if (-1 == parse_validate_attributes(dig)) {
		return -1;
	}

	/* Quality of Protection - qop */
	if (DIGEST_QOP_AUTH == (DIGEST_QOP_AUTH & dig->qop)) {
		qop_value = "auth";
	} else if (DIGEST_QOP_AUTH_INT == (DIGEST_QOP_AUTH_INT & dig->qop)) {
		/* auth-int, which is not supported */
		return -1;
	}

	/* Set algorithm */
	algorithm_value = NULL;
	if (DIGEST_ALGORITHM_MD5 == dig->algorithm) {
		algorithm_value = "MD5";
	}

	/* Generate the minimum digest header string */
	result_size = snprintf(result, max_length, "Digest realm=\"%s\"", dig->realm);
	if (result_size == -1 || result_size == max_length) {
		return -1;
	}

	/* Add opaque */
	if (NULL != dig->opaque) {
		sz = snprintf(result + result_size, max_length - result_size, ", opaque=\"%s\"", dig->opaque);
		result_size += sz;
		if (sz == -1 || result_size >= max_length) {
			return -1;
		}
	}

	/* Add algorithm */
	if (DIGEST_ALGORITHM_NOT_SET != dig->algorithm) {
		sz = snprintf(result + result_size, max_length - result_size, ", algorithm=\"%s\"",\
	    	    algorithm_value);
		if (sz == -1 || result_size >= max_length) {
			return -1;
		}
	}

	/* If qop is supplied, add nonce, cnonce, nc and qop */
	if (DIGEST_QOP_NOT_SET != dig->qop) {
		sz = snprintf(result + result_size, max_length - result_size, ", qop=%s, nonce=\"%s\", cnonce=\"%08x\", nc=%08x",\
		    qop_value,\
		    dig->nonce,\
		    dig->cnonce,\
		    dig->nc);
		if (sz == -1 || result_size >= max_length) {
			return -1;
		}
	}

	return result_size;
}
