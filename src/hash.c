#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "md5.h"
#include "hash.h"

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
 * Hashes method and URI (ex: GET:/api/users).
 *
 * result is the buffer where to store the generated md5 hash.
 * Both method and uri should be null terminated strings.
 */
void
hash_generate_a2(char *result, const char *method, const char *uri)
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
void
hash_generate_a1(char *result, const char *username, const char *realm, const char *password)
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
void
hash_generate_response_auth(char *result, const char *ha1, const char *nonce, unsigned int nc, unsigned int cnonce, const char *qop, const char *ha2)
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
void
hash_generate_response(char *result, const char *ha1, const char *nonce, const char *ha2)
{
	char raw[512];
	sprintf(raw, "%s:%s:%s", ha1, nonce, ha2);
	_get_md5(raw, result);
}
