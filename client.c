#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "parse.h"
#include "hash.h"
#include "client.h"

int
digest_parse(digest_t *digest, const char *digest_string)
{
	digest_s *dig = (digest_s *) digest;

	/* Clear */
	memset(dig, 0, sizeof (digest_s));

	/* Set default values */
	dig->nc = 1;
	dig->cnonce = time(NULL);
	dig->algorithm = DIGEST_ALGORITHM_MD5;
	dig->qop = '\0';

	if (-1 == parse_digest(dig, digest_string)) {
		return -1;
	}

	return 0;
}

/**
 * Checks if a string pointer is NULL or if the length is more than 255 chars.
 *
 * string is the string to check.
 *
 * Returns 0 if not NULL and length is below 256 characters, otherwise -1.
 */
int
_check_string(const char *string)
{
	if (NULL == string || 255 < strlen(string)) {
		return -1;
	}

	return 0;
}

/**
 * Validates the string values in a digest struct.
 *
 * The function goes through the string values and check if they are valid.
 * They are considered valid if they aren't NULL and the character length is
 * below 256.
 *
 * dig is a pointer to the struct where to check the string values.
 *
 * Returns 0 if valid, otherwise -1.
 */
int
_validate_attributes(digest_s *dig)
{
	if (-1 == _check_string(dig->username)) {
		return -1;
	}
	if (-1 == _check_string(dig->password)) {
		return -1;
	}
	if (-1 == _check_string(dig->uri)) {
		return -1;
	}
	if (-1 == _check_string(dig->realm)) {
		return -1;
	}
	if (NULL != dig->opaque && 255 < strlen(dig->opaque)) {
		return -1;
	}

	/* nonce */
	if (DIGEST_QOP_NOT_SET != dig->qop && -1 == _check_string(dig->nonce)) {
		return -1;
	}

	return 0;
}

/**
 * Generates the Authentication header string.
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
digest_get_hval(digest_t *digest, char *result, size_t max_length)
{
	digest_s *dig = (digest_s *) digest;
	char hash_a1[52], hash_a2[52], hash_res[52];
	char *qop_value, *algorithm_value, *method_value;
	size_t result_size; /* The size of the result string */
	int sz;

	/* Check length of char attributes to prevent buffer overflow */
	if (-1 == _validate_attributes(dig)) {
		return -1;
	}

	/* Build Quality of Protection - qop */
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

	/* opaque */
	if (NULL != dig->opaque) {
		sz = snprintf(result + result_size, max_length - result_size, ", opaque=\"%s\"", dig->opaque);
		result_size += sz;
		if (sz == -1 || result_size >= max_length) {
			return -1;
		}
	}

	/* algorithm */
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
