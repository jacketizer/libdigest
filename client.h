#ifndef INC_DIGEST_CLIENT_H
#define INC_DIGEST_CLIENT_H
#include "digest.h"

/**
 * Parse a digest string.
 *
 * @param digest_t *digest The digest context.
 * @param char *digest_string The header value of the WWW-Authenticate header.
 *
 * @returns int 0 on success, otherwise -1.
 */
extern int digest_client_parse(digest_t *digest, const char *digest_string);

/**
 * Generate the Authorization header value.
 *
 * Attributes that must be set manually before calling this function:
 *
 *  - Username
 *  - Password
 *  - URI
 *  - Method
 *
 * @param digest_t *digest The digest context to generate the header value from.
 * @param char *result The buffer to store the generated header value in.
 *
 * Returns the number of bytes in the result string. -1 on failure.
 */
extern size_t digest_client_generate_header(digest_t *digest, char *result, size_t max_length);

#endif  /* INC_DIGEST_CLIENT_H */
