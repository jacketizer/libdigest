#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <digest.h>
#include <digest/client.h>
#include "minunit.h"

int tests_run = 0;

static unsigned char *
test_digest_create_ok()
{
	int rc;
	digest_t d;
	digest_s *dig;
	char digest_str[] = "Digest realm=\"test\", qop=\"auth-int,auth\", nonce=\"9e9cb182c25b68148676a98cda86d501\" opaque=\"9bc51272c609b6b6bb3547fac2102e78\"";

	rc = digest_client_parse(&d, digest_str);
	mu_assert("should be able to create a new digest object", -1 != rc);

	dig = (digest_s *) &d;
	mu_assert("should set the realm attribute correctly", 0 == strcmp(dig->realm, "test"));
	mu_assert("should set the qop attribute correctly", DIGEST_QOP_AUTH == dig->qop);
	mu_assert("should set the nonce attribute correctly", 0 == strcmp(dig->nonce, "9e9cb182c25b68148676a98cda86d501"));
	mu_assert("should set the opaque attribute correctly", 0 == strcmp(dig->opaque, "9bc51272c609b6b6bb3547fac2102e78"));

	return 0;
}

static unsigned char *
all_tests()
{
	mu_group("digest_create()");
	mu_run_test(test_digest_create_ok);

	return 0;
}

int
main(void)
{
	unsigned char *result;

	tests_run = 0;
	result = all_tests();
	if (result != 0) {
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
