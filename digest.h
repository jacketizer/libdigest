#ifndef _DIGEST_TYPES_H
#define _DIGEST_TYPES_H

typedef struct {
	char *username;
	char *password;
	char *realm;
	char *nonce;
	unsigned int cnonce;
	char *opaque;
	char *uri;
	unsigned int method;
	char algorithm;
	unsigned int qop;
	unsigned int nc;
} digest_s;

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

/* Union type for attribute get/set function  */
typedef union {
	int number;
	char *string;
	const char *const_str; // for supress compiler warnings
} digest_attr_value_t;

/* Supported hashing algorithms */
#define DIGEST_ALGORITHM_NOT_SET	0
#define DIGEST_ALGORITHM_MD5		1

/* Quality of Protection (qop) values */
#define DIGEST_QOP_NOT_SET 	0
#define DIGEST_QOP_AUTH 	1
#define DIGEST_QOP_AUTH_INT	2 /* Not supported yet */

/* Method values */
#define DIGEST_METHOD_OPTIONS	1
#define DIGEST_METHOD_GET   	2
#define DIGEST_METHOD_HEAD  	3
#define DIGEST_METHOD_POST  	4
#define DIGEST_METHOD_PUT   	5
#define DIGEST_METHOD_DELETE	6
#define DIGEST_METHOD_TRACE 	7

/**
 * Initiate the digest context.
 *
 */
int digest_init(digest_t *digest);

/**
 * Check if WWW-Authenticate string is digest authentication scheme.
 *
 * @param const char *header_value The value of the WWW-Authentication header.
 *
 * @returns int 0 if digest scheme, otherwise -1.
 */
extern int digest_is_digest(const char *header_value);

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
 * Set an attribute on a digest object.
 *
 * @param digest_t *digest The digest context to set attribute to.
 * @param digest_attr_t attr Which attribute to set.
 * @param const void *value Value to set the attribute to. If the value
 *        is a string, *value should be a C string (char *). If it is
 *        an integer, *value should be a an integer (unsigned int).
 *
 * @returns int 0 on success, otherwise -1.
 */
extern int digest_set_attr(digest_t *digest, digest_attr_t attr, const digest_attr_value_t value);

#endif
