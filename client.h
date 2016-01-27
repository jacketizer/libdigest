#ifndef INC_DIGEST_H
#define INC_DIGEST_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "digest.h"

typedef digest_s* digest_t;

/**
 * The attributes found in a digest string, both WWW-Authenticate and
 * Authorization headers.
 */
typedef enum {
	D_ATTR_USERNAME,
	D_ATTR_PASSWORD,
	D_ATTR_REALM,
	D_ATTR_NONCE,
	D_ATTR_CNONCE,
	D_ATTR_OPAQUE,
	D_ATTR_URI,
	D_ATTR_METHOD,
	D_ATTR_ALGORITHM,
	D_ATTR_QOP,
	D_ATTR_NONCE_COUNT
} digest_attr_t;

/* Supported hashing algorithms */
#define DIGEST_ALGORITHM_NOT_SET	0
#define DIGEST_ALGORITHM_MD5		1

/* Quality of Protection (qop) values */
#define DIGEST_QOP_NOT_SET 	0
#define DIGEST_QOP_AUTH 	1
#define DIGEST_QOP_AUTH_INT	2 /* Not supported yet */

/*
 * Create a new digest object
 *
 * @param char *digest_string The header value of the WWW-Authenticate header.
 *
 * @returns digest_t The digest object used in other calls.
 **/
extern digest_t digest_create(char *digest_string);

/*
 * Get an attribute from a digest object
 *
 * @param digest_t *digest The digest object to get attribute from.
 * @param digest_attr_t attr Which attribute to get.
 *
 * @returns void * The attribute value, a C string or a pointer to an int.
 **/
extern void * digest_get_attr(digest_t digest, digest_attr_t attr);

/*
 * Set an attribute on a digest object
 *
 * @param digest_t *digest The digest object to set attribute to.
 * @param digest_attr_t attr Which attribute to set.
 * @param const void *value Value to set the attribute to. If the value
 *        is a string, *value should be a C string (char *). If it is
 *        an integer, *value should be a pointer to an integer (unsigned int *).
 *
 * @returns int 0 on success, otherwise -1.
 **/
extern int digest_set_attr(digest_t digest, digest_attr_t attr, const void *value);

/*
 * Checks if WWW-Authenticate string is digest authentication scheme
 *
 * @param const char *header_value The value of the WWW-Authentication header.
 *
 * @returns int 0 if digest scheme, otherwise -1.
 **/
extern int digest_is_digest(char *header_value);

/*
 * Generate the Authorization header value
 *
 * @param digest_t *digest The digest object to generate the header value from.
 *
 * @returns char * the header string. Should be free'd manually.
 **/
extern char * digest_get_hval(digest_t digest);

#endif  /* INC_DIGEST_H */
