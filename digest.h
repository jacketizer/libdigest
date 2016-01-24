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
	char *method;
	char *algorithm;
	char qop;
	unsigned int nc;
} digest_s;

#endif
