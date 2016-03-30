#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "parse.h"
#include "hash.h"
#include "client.h"

int
digest_client_parse(digest_t *digest, const char *digest_string)
{
	digest_s *dig = (digest_s *) digest;

	/* Set default values */
	dig->nc = 1;
	dig->cnonce = time(NULL);

	return parse_digest(dig, digest_string);
}

/**
 * Generates the Authorization header string.
 *
 * Attributes that must be set manually before calling this function:
 *
 *  - Username
 *  - Password
 *  - URI
 *  - Method
 *
 * If not set, NULL will be returned.
 *
 * Returns the number of bytes in the result string.
 */
size_t
digest_client_generate_header(digest_t *digest, char *result, size_t max_length)
{
	digest_s *dig = (digest_s *) digest;
	char hash_a1[52], hash_a2[52], hash_res[52];
	char *qop_value, *algorithm_value, *method_value;
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

	/* Set method */
	switch (dig->method) {
	case DIGEST_METHOD_OPTIONS:
		method_value = "OPTIONS";
		break;
	case DIGEST_METHOD_GET:
		method_value = "GET";
		break;
	case DIGEST_METHOD_HEAD:
		method_value = "HEAD";
		break;
	case DIGEST_METHOD_POST:
		method_value = "POST";
		break;
	case DIGEST_METHOD_PUT:
		method_value = "PUT";
		break;
	case DIGEST_METHOD_DELETE:
		method_value = "DELETE";
		break;
	case DIGEST_METHOD_TRACE:
		method_value = "TRACE";
		break;
	default:
		return -1;
	}

	/* Generate the hashes */
	hash_generate_a1(hash_a1, dig->username, dig->realm, dig->password);
	hash_generate_a2(hash_a2, method_value, dig->uri);

	if (DIGEST_QOP_NOT_SET != dig->qop) {
		hash_generate_response_auth(hash_res, hash_a1, dig->nonce, dig->nc, dig->cnonce, qop_value, hash_a2);
	} else {
		hash_generate_response(hash_res, hash_a1, dig->nonce, hash_a2);
	}

	/* Generate the minimum digest header string */
	result_size = snprintf(result, max_length, "Digest username=\"%s\", realm=\"%s\", uri=\"%s\", response=\"%s\"",\
	    dig->username,\
	    dig->realm,\
	    dig->uri,\
	    hash_res);
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
