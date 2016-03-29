#ifndef INC_DIGEST_PARSE_H
#define INC_DIGEST_PARSE_H
#include "digest.h"

#define ARRAY_LENGTH(a) (sizeof a / sizeof (a[0]))

int parse_digest(digest_s *dig, const char *digest_string);
int parse_validate_attributes(digest_s *dig);

#endif  /* INC_DIGEST_PARSE_H */
