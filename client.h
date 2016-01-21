#ifndef INC_DIGEST_H
#define INC_DIGEST_H
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "digest.h"

typedef digest_s* digest_t;

/**
 * The different attributes found in a digest string that can be set by
 * the user.
 */
typedef enum {
  D_ATTR_USERNAME,
  D_ATTR_PASSWORD,
  D_ATTR_NONCE,
  D_ATTR_URI,
  D_ATTR_METHOD,
} digest_attr_t;

#define DIGEST_ALGORITHM_MD5 "MD5"
#define DIGEST_QOP_AUTH "auth"

/*
 * Create a new digest object
 *
 * @param char *digest_string The header value of the WWW-Authenticate header.
 *
 * @returns digest_t The digest object used in other calls.
 **/
extern digest_t digest_create(char *digest_string);

extern char * digest_get_attr(digest_t digest, digest_attr_t attr);

extern int digest_set_attr(digest_t digest, digest_attr_t attr, const char *value);

extern char * digest_get_hval(digest_t digest);

#endif  /* INC_DIGEST_H */
