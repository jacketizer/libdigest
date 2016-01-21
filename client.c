#include "md5.h"
#include "client.h"

/**
 * MD5 hash a string.
 *
 * string needs to be null terminated.
 *
 * Returns a pointer to the MD5 string, needs to be manually free'd.
 */
static char *
_get_md5(const char *string)
{
	// MD5 Test code
	unsigned char digest[16];
	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update(&context, string, strlen(string));
	MD5_Final(digest, &context);

	int i = 0;
	char *md5string = malloc(52);
	for (i = 0; i < 16; ++i) {
		sprintf(&md5string[i*2], "%02x", (unsigned int) digest[i]);
	}

	return md5string;
}

/**
 * Get value from digest key/value string.
 *
 * value is the string to parse the value from, ex: "key=value".
 *
 * Returns a pointer to the start of the value, null terminated.
 */
static char *
_dgst_get_val(char *value)
{
	char *cursor = value;

	/* find start of value */
	while (*cursor != '=') {
		cursor++;
	}
	cursor++;

	if (*cursor != '"') {
		return cursor;
	}
	cursor++;

	int len = strlen(cursor);
	cursor[len - 1] = '\0';

	return cursor;
}

/**
 * Splits a sentence by comma.
 *
 * sentence is the string to split, null terminated.
 * values is a char pointer array that will be filled with pointers to the
 * splitted values in the sentence string.
 *
 * Returns the number of values found in sentence.
 */
static inline int
_split_sentence(char *sentence, char **values)
{
	int i = 0;
	sentence = strdup(sentence + 7); // skip Digest word
	char *cursor = sentence;
	int length = strlen(sentence);

	while (*cursor != '\0' && cursor - sentence < length) {
		/* rewind to after spaces */
		while (*cursor == ' ' || *cursor == ',') {
			cursor++;
		}
		values[i++] = cursor;

		/* find comma */
		cursor = (char *) memchr(cursor, ',', length - (cursor - sentence));
		if (NULL == cursor) {
			/* end of string */
			break;
		}

		*cursor = '\0';
		cursor++;
	}

	return i;
}

/**
 * Hash method and URI (ex: GET:/api/users).
 *
 * Both method and uri should be null terminated strings.
 *
 * Returns the hash as a null terminated string. Should be free'd manually.
 */
static inline char *
_dgst_ha2(char *method, char *uri)
{
	char raw[512];
	sprintf(raw, "%s:%s", method, uri);
	return _get_md5(raw);
}

// MD5(username:REALM:password):
static inline char *
_dgst_ha1(char *username, char *realm, char *password)
{
  char raw[512];
  sprintf(raw, "%s:%s:%s", username, realm, password);
  return _get_md5(raw);
}

// MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)
static inline char *
_dgst_response(char *ha1, char *nonce, unsigned int nc, unsigned int cnonce, char *qop, char *ha2)
{
  char raw[512];
  sprintf(raw, "%s:%s:%08x:%08x:%s:%s", ha1, nonce, nc, cnonce, qop, ha2);
  return _get_md5(raw);
}

int
_dgst_fill(digest_s *dig, char *digest_string)
{
  char **values = malloc(127);
  int n = _split_sentence(digest_string, values);

  int i = 0;
  char *val;
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
      dig->qop = _dgst_get_val(val);
    } else if (0 == strncmp("opaque=", val, 4)) {
      dig->opaque = _dgst_get_val(val);
    }
  }

  free(values);

  /* Only support qop=auth for now */
  if (0 != strcmp(DIGEST_QOP_AUTH, dig->qop)) {
    return -1;
  }

  return i;
}

char *
digest_get_attr(digest_t digest, digest_attr_t attr)
{
	digest_s *dig = (digest_s *) digest;

	switch (attr) {
		case D_ATTR_USERNAME:
			return dig->username;
		case D_ATTR_PASSWORD:
			return dig->password;
		case D_ATTR_NONCE:
			return dig->nonce;
		case D_ATTR_URI:
			return dig->uri;
		case D_ATTR_METHOD:
			return dig->uri;
		default:
			return NULL;
	}
}

int
digest_set_attr(digest_t digest, digest_attr_t attr, const char *value)
{
	digest_s *dig = (digest_s *) digest;

	switch (attr) {
		case D_ATTR_USERNAME:
			dig->username = strdup(value);
			break;
		case D_ATTR_PASSWORD:
			dig->password = strdup(value);
			break;
		case D_ATTR_NONCE:
			dig->nonce = strdup(value);
			break;
		case D_ATTR_URI:
			dig->uri = strdup(value);
			break;
		case D_ATTR_METHOD:
			dig->method = strdup(value);
			break;
		default:
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

  if (-1 == _dgst_fill(dig, digest_string)) {
    free(dig);
    return (digest_t) NULL;
  }

  /* Initialize */
  dig->nc = 1;
  dig->cnonce = time(NULL);
  dig->algorithm = strdup(DIGEST_ALGORITHM_MD5); // Only support MD5

  return (digest_t) dig;
}

// HA1 (username:REALM:password):
// HA2 (METHOD:/url/to/services)
//
// Response: MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)
char *
digest_get_hval(digest_t digest)
{
  digest_s *dig = (digest_s *) digest;

  char *ha1, *ha2, *res;

  ha1 = _dgst_ha1(dig->username, dig->realm, dig->password);
  ha2 = _dgst_ha2(dig->method, dig->uri);
  res = _dgst_response(ha1, dig->nonce, dig->nc, dig->cnonce, dig->qop, ha2);

  char *authval = malloc(4096);
  sprintf(authval, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", algorithm=%s, response=\"%s\", qop=%s, nc=%08x, cnonce=\"%08x\", uri=\"%s\"", dig->username, dig->realm, dig->nonce, dig->algorithm, res, dig->qop, dig->nc, dig->cnonce, dig->uri);

  free(ha1);
  free(ha2);
  free(res);

  /* Increase the count */
  dig->nc++;

  return authval;
}
