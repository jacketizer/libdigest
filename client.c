#include "md5.h"
#include "client.h"

#define ARRAY_LENGTH(a) (sizeof a / sizeof (a[0]))

/**
 * Generates an MD5 hash from a string.
 *
 * string needs to be null terminated.
 * result is the buffer where to store the md5 hash. The length will always be
 * 32 characters long.
 */
static void
_get_md5(const char *string, char *result)
{
	int i = 0;
	unsigned char digest[16];

	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update(&context, string, strlen(string));
	MD5_Final(digest, &context);

	for (i = 0; i < 16; ++i) {
		sprintf(&result[i * 2], "%02x", (unsigned int) digest[i]);
	}
}

/**
 * Extracts the value part from a attribute-value pair.
 *
 * parameter is the string to parse the value from, ex: "key=value".
 *           The string needs to be null-terminated. Can be both
 *           key=value and key="value".
 *
 * Returns a pointer to the start of the value on success, otherwise NULL.
 */
static char *
_dgst_get_val(char *parameter)
{
	char *cursor, *q;

	/* Find start of value */
	if (NULL == (cursor = strchr(parameter, '='))) {
		return (char *) NULL;
	}

	if (*(++cursor) != '"') {
		return cursor;
	}

	cursor++;
	if (NULL == (q = strchr(cursor, '"'))) {
		return (char *) NULL;
	}
	*q = '\0';

	return cursor;
}

/**
 * Removes the authentication scheme identification token from the
 * WWW-Authenticate header field value.
 *
 * header_value is the WWW-Authenticate header field value.
 *
 * Returns a pointer to a new string containing only
 * the authentication parameters. Must be free'd manually.
 */
static char *
_crop_sentence(const char *header_value)
{
 	/* Skip Digest word, and duplicate string */
	return strdup(header_value + 7);
}

/**
 * Splits a string by comma.
 *
 * sentence is the string to split, null terminated.
 * values is a char pointer array that will be filled with pointers to the
 * splitted values in the sentence string.
 * max_values is the length of the **values array. The function will not parse
 * more than max_values entries.
 *
 * Returns the number of values found in string.
 */
static inline int
_split_string_by_comma(char *sentence, char **values, int max_values)
{
	int i = 0;

	while (i < max_values && '\0' != *sentence) {
		/* Rewind to after spaces */
		while (' ' == *sentence || ',' == *sentence) {
			sentence++;
		}

		/* Check for end of string */
		if ('\0' == *sentence) {
			break;
		}

		values[i++] = sentence;

		/* Find comma */
		if (NULL == (sentence = strchr(sentence, ','))) {
			/* End of string */
			break;
		}

		*(sentence++) = '\0';
	}

	return i;
}

/**
 * Tokenizes a string containing comma-seperated attribute-key parameters.
 *
 * sentence is the string to split, null terminated.
 * values is a char pointer array that will be filled with pointers to the
 * splitted values in the sentence string.
 * max_values is the length of the **values array. The function will not parse
 * more than max_values entries.
 *
 * Returns the number of values found in sentence.
 */
static inline unsigned int
_tokenize_sentence(char *sentence, char **values, unsigned int max_values)
{
	unsigned int i = 0;
	char *cursor = sentence;

	while (i < max_values && *cursor != '\0') {
		/* Rewind to after spaces */
		while (' ' == *cursor || ',' == *cursor) {
			cursor++;
		}

		/* Check for end of string */
		if ('\0' == *cursor) {
			break;
		}

		values[i++] = cursor;

		/* Find equal sign (=) */
		if (NULL == (cursor = strchr(cursor, '='))) {
			/* End of string */
			break;
		}

		/* Check if a quotation mark follows the = */
		if ('\"' == *(++cursor)) {
			/* Find next quotation mark */
			if (NULL == (cursor = strchr(++cursor, '\"'))) {
				/* End of string */
				break;
			}
			/* Comma should be after */
			cursor++;
		} else {
			/* Find comma */
			if (NULL == (cursor = strchr(cursor, ','))) {
				/* End of string */
				break;
			}
		}

		*(cursor++) = '\0';
	}

	return i;
}

/**
 * Hashes method and URI (ex: GET:/api/users).
 *
 * result is the buffer where to store the generated md5 hash.
 * Both method and uri should be null terminated strings.
 */
static inline void
_dgst_generate_a2(char *result, const char *method, const char *uri)
{
	char raw[512];
	sprintf(raw, "%s:%s", method, uri);
	_get_md5(raw, result);
}

/**
 * Hashes username, realm and password (ex: jack:GET:password).
 *
 * result is the buffer where to store the generated md5 hash.
 * All other arguments should be null terminated strings.
 */
static inline void
_dgst_generate_a1(char *result, const char *username, const char *realm, const char *password)
{
	char raw[768];
	sprintf(raw, "%s:%s:%s", username, realm, password);
	_get_md5(raw, result);
}

/**
 * Generates the response parameter according to rfc.
 *
 * Hashes a1, nonce, nc, cnonce, qop and a2. This should be used when the
 * qop parameter is supplied.
 *
 * result is the buffer where to store the generated md5 hash.
 * All other arguments should be null terminated strings.
 */
static inline void
_dgst_generate_response_auth(char *result, const char *ha1, const char *nonce, unsigned int nc, unsigned int cnonce, const char *qop, const char *ha2)
{
	char raw[512];
	sprintf(raw, "%s:%s:%08x:%08x:%s:%s", ha1, nonce, nc, cnonce, qop, ha2);
	_get_md5(raw, result);
}

/**
 * Generates the response parameter according to rfc.
 *
 * Hashes a1, nonce and a2. This is the version used when the qop parameter is
 * not supplied.
 *
 * result is the buffer where to store the generated md5 hash.
 * All other arguments should be null terminated strings.
 */
static inline void
_dgst_generate_response(char *result, const char *ha1, const char *nonce, const char *ha2)
{
	char raw[512];
	sprintf(raw, "%s:%s:%s", ha1, nonce, ha2);
	_get_md5(raw, result);
}

/**
 * Parses a WWW-Authenticate header value to a struct.
 *
 * dig is a pointer to the digest struct to fill the parsed values with.
 * digest_string should be the value from the WWW-Authentication header,
 * null terminated.
 *
 * Returns the hash as a null terminated string. Should be free'd manually.
 */
int
_dgst_parse(digest_s *dig, const char *digest_string)
{
	int n, i = 0;
	char *val, *parameters;
	char *values[12];

	parameters = _crop_sentence(digest_string);
	n = _tokenize_sentence(parameters, values, ARRAY_LENGTH(values));

	while (i < n) {
		if (NULL == (val = values[i++])) {
			continue;
		}

		if (0 == strncmp("nonce=", val, strlen("nonce="))) {
			dig->nonce = _dgst_get_val(val);
		} else if (0 == strncmp("realm=", val, strlen("realm="))) {
			dig->realm = _dgst_get_val(val);
		} else if (0 == strncmp("qop=", val, strlen("qop="))) {
			char *qop_options = _dgst_get_val(val);
			char *qop_values[2];
			int n_qops = _split_string_by_comma(qop_options, qop_values, ARRAY_LENGTH(qop_values));
			while (n_qops-- > 0) {
				if (0 == strncmp(qop_values[n_qops], "auth", strlen("auth"))) {
					dig->qop |= DIGEST_QOP_AUTH;
					continue;
				}
				if (0 == strncmp(qop_values[n_qops], "auth-int", strlen("auth-int"))) {
					dig->qop |= DIGEST_QOP_AUTH_INT;
				}
			}
		} else if (0 == strncmp("opaque=", val, strlen("opaque="))) {
			dig->opaque = _dgst_get_val(val);
		} else if (0 == strncmp("algorithm=", val, strlen("algorithm="))) {
			char *algorithm = _dgst_get_val(val);
			if (0 == strncmp(algorithm, "MD5", strlen("MD5"))) {
				dig->algorithm = DIGEST_ALGORITHM_MD5;
			}
		}
	}

	return i;
}

int
digest_is_digest(const char *header_value)
{
	if (NULL == header_value) {
		return -1;
	}

	if (0 != strncmp(header_value, "Digest", 6)) {
		return -1;
	}

	return 0;
}

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

	if (-1 == _dgst_parse(dig, digest_string)) {
		return -1;
	}

	return 0;
}

void *
digest_get_attr(digest_t *digest, digest_attr_t attr)
{
	digest_s *dig = (digest_s *) digest;

	switch (attr) {
	case D_ATTR_USERNAME:
		return dig->username;
	case D_ATTR_PASSWORD:
		return dig->password;
	case D_ATTR_REALM:
		return dig->realm;
	case D_ATTR_NONCE:
		return dig->nonce;
	case D_ATTR_CNONCE:
		return &(dig->cnonce);
	case D_ATTR_OPAQUE:
		return dig->opaque;
	case D_ATTR_URI:
		return dig->uri;
	case D_ATTR_METHOD:
		return &(dig->method);
	case D_ATTR_ALGORITHM:
		return &(dig->algorithm);
	case D_ATTR_QOP:
		return &(dig->qop);
	case D_ATTR_NONCE_COUNT:
		return &(dig->nc);
	default:
		return NULL;
	}
}

int
digest_set_attr(digest_t *digest, digest_attr_t attr, const digest_attr_value_t value)
{
	digest_s *dig = (digest_s *) digest;

	switch (attr) {
	case D_ATTR_USERNAME:
		dig->username = value.string;
		break;
	case D_ATTR_PASSWORD:
		dig->password = value.string;
		break;
	case D_ATTR_REALM:
		dig->realm = value.string;
		break;
	case D_ATTR_NONCE:
		dig->nonce = value.string;
		break;
	case D_ATTR_CNONCE:
		dig->cnonce = value.number;
		break;
	case D_ATTR_OPAQUE:
		dig->opaque = value.string;
		break;
	case D_ATTR_URI:
		dig->uri = value.string;
		break;
	case D_ATTR_METHOD:
		dig->method = value.number;
		break;
	case D_ATTR_ALGORITHM:
		dig->algorithm = value.number;
		break;
	case D_ATTR_QOP:
		dig->qop = value.number;
		break;
	case D_ATTR_NONCE_COUNT:
		dig->nc = value.number;
		break;
	default:
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
	_dgst_generate_a1(hash_a1, dig->username, dig->realm, dig->password);
	_dgst_generate_a2(hash_a2, method_value, dig->uri);

	if (DIGEST_QOP_NOT_SET != dig->qop) {
		_dgst_generate_response_auth(hash_res, hash_a1, dig->nonce, dig->nc, dig->cnonce, qop_value, hash_a2);
	} else {
		_dgst_generate_response(hash_res, hash_a1, dig->nonce, hash_a2);
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
