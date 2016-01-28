#include "md5.h"
#include "client.h"

/**
 * Generates an MD5 hash from a string.
 *
 * string needs to be null terminated.
 *
 * Returns a pointer to the MD5 string on success, otherwise NULL. Needs to be
 * manually free'd.
 */
static char *
_get_md5(const char *string)
{
	int i = 0;
	char *md5_string;
	unsigned char digest[16];

	md5_string = malloc(52);
	if (NULL == md5_string) {
		return (char *) NULL;
	}

	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update(&context, string, strlen(string));
	MD5_Final(digest, &context);

	for (i = 0; i < 16; ++i) {
		sprintf(&md5_string[i * 2], "%02x", (unsigned int) digest[i]);
	}

	return md5_string;
}

/**
 * Extracts the value part from a attribute-value pair.
 *
 * parameter is the string to parse the value from, ex: "key=value".
 *
 * Returns a pointer to the start of the value on success, otherwise NULL.
 */
static char *
_dgst_get_val(char *parameter)
{
	char *cursor;

	/* Find start of value */
	cursor = strchr(parameter, '=');
	if (NULL == cursor) {
		return (char *) NULL;
	}

	cursor++;
	if (*cursor != '"') {
		return cursor;
	}
	cursor++;

	char *q = strchr(cursor, '"');
	if (NULL == q) {
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
 * the authentication parameters.
 */
static char *
_crop_sentence(char *header_value)
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
 * Returns the number of values found in sentence.
 */
static inline int
_split_sentence(char *sentence, char **values, int max_values)
	{
	int i = 0;
	char *cursor = sentence;
	int length = strlen(sentence);

	while (i < max_values && *cursor != '\0' && cursor - sentence < length) {
		/* Rewind to after spaces */
		while (*cursor == ' ' || *cursor == ',') {
			cursor++;
		}

		values[i++] = cursor;

		/* Find comma */
		cursor = (char *) memchr(cursor, ',', length - (cursor - sentence));
		if (NULL == cursor) {
			/* End of string */
			break;
		}

		*cursor = '\0';
		cursor++;
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
static inline int
_tokenize_sentence(char *sentence, char **values, int max_values)
{
	int i = 0;
	char *cursor = sentence;
	int length = strlen(sentence);

	while (i < max_values && *cursor != '\0' && cursor - sentence < length) {
		/* Rewind to after spaces */
		while (*cursor == ' ' || *cursor == ',') {
			cursor++;
		}

		values[i++] = cursor;

		/* Find equal sign (=) */
		cursor = (char *) memchr(cursor, '=', length - (cursor - sentence));
		if (NULL == cursor) {
			/* End of string */
			break;
		}

		/* Check if a quotation mark follows the = */
		cursor++;
		if ('\"' == *cursor) {
			/* Find next quotation mark */
			cursor++;
			cursor = (char *) memchr(cursor, '\"', length - (cursor - sentence));
			if (NULL == cursor) {
				/* End of string */
				break;
			}
			/* Comma should be after */
			cursor++;
		} else {
			/* Find comma */
			cursor = (char *) memchr(cursor, ',', length - (cursor - sentence));
			if (NULL == cursor) {
				/* End of string */
				break;
			}
		}

		*cursor = '\0';
		cursor++;
	}

	return i;
}

/**
 * Hashes method and URI (ex: GET:/api/users).
 *
 * Both method and uri should be null terminated strings.
 *
 * Returns the hash as a null terminated string. Should be free'd manually.
 */
static inline char *
_dgst_generate_a2(char *method, char *uri)
{
	char raw[512];
	sprintf(raw, "%s:%s", method, uri);
	return _get_md5(raw);
}

/**
 * Hashes username, realm and password (ex: jack:GET:password).
 *
 * All arguments should be null terminated strings.
 *
 * Returns the hash as a null terminated string. Should be free'd manually.
 */
static inline char *
_dgst_generate_a1(char *username, char *realm, char *password)
{
	char raw[512];
	sprintf(raw, "%s:%s:%s", username, realm, password);
	return _get_md5(raw);
}

/**
 * Generates the response parameter according to rfc.
 *
 * Hashes a1, nonce, nc, cnonce, qop and a2. This should be used when the
 * qop parameter is supplied.
 *
 * All arguments should be null terminated strings.
 *
 * Returns the hash as a null terminated string. Should be free'd manually.
 */
static inline char *
_dgst_generate_response_auth(char *ha1, char *nonce, unsigned int nc, unsigned int cnonce, char *qop, char *ha2)
{
	char raw[512];
	sprintf(raw, "%s:%s:%08x:%08x:%s:%s", ha1, nonce, nc, cnonce, qop, ha2);
	return _get_md5(raw);
}

/**
 * Generates the response parameter according to rfc.
 *
 * Hashes a1, nonce and a2. This is the version used when the qop parameter is
 * not supplied.
 *
 * All arguments should be null terminated strings.
 *
 * Returns the hash as a null terminated string. Should be free'd manually.
 */
static inline char *
_dgst_generate_response(char *ha1, char *nonce, char *ha2)
{
	char raw[512];
	sprintf(raw, "%s:%s:%s", ha1, nonce, ha2);
	return _get_md5(raw);
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
_dgst_parse(digest_s *dig, char *digest_string)
{
	int i = 0;
	char *val;
	char *values[12];
	int n = _tokenize_sentence(_crop_sentence(digest_string), values, 12);

	while (i < n) {
		val = values[i++];
		if (NULL == val) {
			continue;
		}

		if (0 == strncmp("nonce=", val, 6)) {
			dig->nonce = _dgst_get_val(val);
		} else if (0 == strncmp("realm=", val, 6)) {
			dig->realm = _dgst_get_val(val);
		} else if (0 == strncmp("qop=", val, 4)) {
			char *qop_options = _dgst_get_val(val);
			char *qop_values[2];
			int n_qops = _split_sentence(qop_options, qop_values, 2);
			while (n_qops-- > 0) {
				if (0 == strncmp(qop_values[n_qops], "auth", 4)) {
					dig->qop |= DIGEST_QOP_AUTH;
					continue;
				}
				if (0 == strncmp(qop_values[n_qops], "auth-int", 8)) {
					dig->qop |= DIGEST_QOP_AUTH_INT;
				}
			}
		} else if (0 == strncmp("opaque=", val, 7)) {
			dig->opaque = _dgst_get_val(val);
		} else if (0 == strncmp("algorithm=", val, 10)) {
			char *algorithm = _dgst_get_val(val);
			if (0 == strncmp(algorithm, "MD5", 3)) {
				dig->algorithm = DIGEST_ALGORITHM_MD5;
			}
		}
	}

	return i;
}

int
digest_is_digest(char *header_value)
{
  if (NULL == header_value) {
    return -1;
  }
  if (0 != strncmp(header_value, "Digest", 6)) {
    return -1;
  }

  return 0;
}

digest_t
digest_create(char *digest_string)
{
	digest_s *dig = (digest_s *) malloc(sizeof (digest_s));
	if (NULL == dig) {
		return (digest_t) NULL;
	}

	/* Initialize */
	memset(dig, 0, sizeof (digest_s));
	dig->nc = 1;
	dig->cnonce = time(NULL);
	dig->algorithm = DIGEST_ALGORITHM_MD5;
	dig->qop = '\0';

	if (-1 == _dgst_parse(dig, digest_string)) {
		free(dig);
		return (digest_t) NULL;
	}

	return (digest_t) dig;
}

void *
digest_get_attr(digest_t digest, digest_attr_t attr)
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
digest_set_attr(digest_t digest, digest_attr_t attr, const void *value)
{
	digest_s *dig = (digest_s *) digest;

	switch (attr) {
	case D_ATTR_USERNAME:
		dig->username = strdup((const char *) value);
		break;
	case D_ATTR_PASSWORD:
		dig->password = strdup((const char *) value);
		break;
	case D_ATTR_REALM:
		dig->realm = strdup((const char *) value);
		break;
	case D_ATTR_NONCE:
		dig->nonce = strdup((const char *) value);
		break;
	case D_ATTR_CNONCE:
		dig->cnonce = (unsigned int) value;
		break;
	case D_ATTR_OPAQUE:
		dig->opaque = strdup((const char *) value);
		break;
	case D_ATTR_URI:
		dig->uri = strdup((const char *) value);
		break;
	case D_ATTR_METHOD:
		dig->method = (unsigned int) value;
		break;
	case D_ATTR_ALGORITHM:
		dig->algorithm = (unsigned int) value;
		break;
	case D_ATTR_QOP:
		dig->qop = (unsigned int) value;
		break;
	case D_ATTR_NONCE_COUNT:
		dig->nc = (unsigned int) value;
		break;
	default:
		return -1;
	}

	return 0;
}

char *
digest_get_hval(digest_t digest)
{
	digest_s *dig = (digest_s *) digest;
	char *hash_a1, *hash_a2, *hash_res;
	char *header_val;
	char *qop_value, *algorithm_value, *method_value;

	/* Build Quality of Protection - qop */
	if (DIGEST_QOP_AUTH == DIGEST_QOP_AUTH & dig->qop) {
		qop_value = "auth";
	} else if (DIGEST_QOP_AUTH_INT == DIGEST_QOP_AUTH_INT & dig->qop) {
		/* auth-int, which is not supported */
		return (char *) NULL;
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
    return (char *) NULL;
  }

	/* Generate the hashes */
	hash_a1 = _dgst_generate_a1(dig->username, dig->realm, dig->password);
	hash_a2 = _dgst_generate_a2(method_value, dig->uri);

	if (DIGEST_QOP_NOT_SET != dig->qop) {
		hash_res = _dgst_generate_response_auth(hash_a1, dig->nonce, dig->nc, dig->cnonce, qop_value, hash_a2);
	} else {
		hash_res = _dgst_generate_response(hash_a1, dig->nonce, hash_a2);
	}

	header_val = malloc(4096);
	if (NULL == header_val) {
		/* Could not allocate memory for result string */
		return (char *) NULL;
	}

	/* Generate the minimum digest header string */
	sprintf(header_val, "Digest \
	    username=\"%s\", \
	    realm=\"%s\", \
	    uri=\"%s\", \
	    response=\"%s\"",\
	    dig->username,\
	    dig->realm,\
	    dig->uri,\
	    hash_res);

	/* opaque */
	if (NULL != dig->opaque) {
		sprintf(header_val + strlen(header_val), ", \
	    	    opaque=\"%s\"",\
	    	    dig->opaque);
	}

	/* algorithm */
	if (DIGEST_ALGORITHM_NOT_SET != dig->algorithm) {
		sprintf(header_val + strlen(header_val), ", \
	    	    algorithm=\"%s\"",\
	    	    algorithm_value);
	}

	/* If qop is supplied, add nonce, cnonce, nc and qop */
	if (DIGEST_QOP_NOT_SET != dig->qop) {
		sprintf(header_val + strlen(header_val), ", \
		    qop=%s, \
		    nonce=\"%s\", \
		    cnonce=\"%08x\", \
		    nc=%08x",\
		    qop_value,\
		    dig->nonce,\
		    dig->cnonce,\
		    dig->nc);
	}

	free(hash_a1);
	free(hash_a2);
	free(hash_res);

	/* Increase the count */
	dig->nc++;

	return header_val;
}
