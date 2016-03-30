#include <stdlib.h>
#include <string.h>
#include "digest.h"

int
digest_init(digest_t *digest)
{
	digest_s *dig = (digest_s *) digest;

	/* Clear */
	memset(dig, 0, sizeof (digest_s));

	/* Set default values */
	dig->algorithm = DIGEST_ALGORITHM_MD5;

	return 0;
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
