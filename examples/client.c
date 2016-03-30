#include <stdlib.h>
#include <stdio.h>
#include <digest.h>
#include <digest/client.h>

int
main(int argc, char **argv)
{
	digest_t d; /* the digest context */
	char result[4096];
	char digest_str[] = "Digest realm=\"test\", qop=\"auth,auth-int\", nonce=\"9e9cb182c25b68148676a98cda86d501\"";

	printf("WWW-Authentication:\n%s\n", digest_str);

	if (-1 == digest_is_digest(digest_str)) {
		fprintf(stderr, "Is not a digest string!\n");
		exit(1);
	}

	if (-1 == digest_init(&d)) {
		fprintf(stderr, "Could not init digest context!\n");
		exit(1);
	}

	if (0 != digest_client_parse(&d, digest_str)) {
		fprintf(stderr, "Could not parse digest string!\n");
		exit(1);
	}

	digest_set_attr(&d, D_ATTR_USERNAME, (digest_attr_value_t) "jack");
	digest_set_attr(&d, D_ATTR_PASSWORD, (digest_attr_value_t) "Passw0rd");
	digest_set_attr(&d, D_ATTR_URI, (digest_attr_value_t) "/api/resource");
	digest_set_attr(&d, D_ATTR_METHOD, (digest_attr_value_t) DIGEST_METHOD_POST);

	if (-1 == digest_client_generate_header(&d, result, sizeof (result))) {
		fprintf(stderr, "Could not build the Authorization header!\n");
		exit(1);
	}

	printf("Authorization:\n%s\n", result);

	return 0;
}
