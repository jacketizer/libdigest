#ifndef INC_DIGEST_H
#define INC_DIGEST_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "digest.h"

/* Digest context type (digest struct) */
typedef digest_s digest_t;

/* The attributes found in a digest string, both WWW-Authenticate and
    Authorization headers.
 */
typedef enum {
	D_ATTR_USERNAME,	/* char * */
	D_ATTR_PASSWORD,	/* char * */
	D_ATTR_REALM,		/* char * */
	D_ATTR_NONCE,		/* char * */
	D_ATTR_CNONCE,		/* int */
	D_ATTR_OPAQUE,		/* char * */
	D_ATTR_URI,		/* char * */
	D_ATTR_METHOD,		/* int */
	D_ATTR_ALGORITHM,	/* int */
	D_ATTR_QOP,		/* int */
	D_ATTR_NONCE_COUNT	/* int */
} digest_attr_t;

/* Supported hashing algorithms */
#define DIGEST_ALGORITHM_NOT_SET	0
#define DIGEST_ALGORITHM_MD5		1

/* Quality of Protection (qop) values */
#define DIGEST_QOP_NOT_SET 	0
#define DIGEST_QOP_AUTH 	1
#define DIGEST_QOP_AUTH_INT	2 /* Not supported yet */

/* Method values */
#define DIGEST_METHOD_OPTIONS 	1
#define DIGEST_METHOD_GET 	2
#define DIGEST_METHOD_HEAD 	3
#define DIGEST_METHOD_POST 	4
#define DIGEST_METHOD_PUT 	5
#define DIGEST_METHOD_DELETE 	6
#define DIGEST_METHOD_TRACE 	7

/**
 * Parse a digest string.
 *
 * @param digest_t *digest The digest context.
 * @param char *digest_string The header value of the WWW-Authenticate header.
 *
 * @returns int 0 on success, otherwise -1.
 */
extern int digest_parse(digest_t *digest, const char *digest_string);

/**
 * Get an attribute from a digest context.
 *
 * @param digest_t *digest The digest context to get attribute from.
 * @param digest_attr_t attr Which attribute to get.
 *
 * @returns void * The attribute value, a C string or a pointer to an int.
 */
extern void * digest_get_attr(digest_t *digest, digest_attr_t attr);

/**
 * Free a digest context.
 *
 * @param digest_t *digest The digest context to free.
 */
void digest_free(digest_t *digest);

/**
 * Set an attribute on a digest object.
 *
 * @param digest_t *digest The digest context to set attribute to.
 * @param digest_attr_t attr Which attribute to set.
 * @param const void *value Value to set the attribute to. If the value
 *        is a string, *value should be a C string (char *). If it is
 *        an integer, *value should be a pointer to an integer (unsigned int *).
 *
 * @returns int 0 on success, otherwise -1.
 */
extern int digest_set_attr(digest_t *digest, digest_attr_t attr, const void *value);

/**
 * Check if WWW-Authenticate string is digest authentication scheme.
 *
 * @param const char *header_value The value of the WWW-Authentication header.
 *
 * @returns int 0 if digest scheme, otherwise -1.
 */
extern int digest_is_digest(const char *header_value);

/**
 * Generate the Authorization header value.
 *
 * @param digest_t *digest The digest context to generate the header value from.
 * @param char *result The buffer to store the generated header value in.
 *
 * Returns the number of bytes in the result string. -1 on failure.
 */
extern int digest_get_hval(digest_t *digest, char *result, int max_length);

#endif  /* INC_DIGEST_H */
