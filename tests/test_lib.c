#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <digest.h>
#include <digest/client.h>
#include "minunit.h"

int tests_run = 0;

static char *
test_digest_get_hval_ok()
{
	char *digest;
	int ret;

	digest = strdup("Digest realm=\"Realm of the Test\"");
	mu_assert("should return a pointer that is not NULL", NULL != ret);
	free(digest);

	return 0;
}

static char *
all_tests()
{
	mu_group("digest_get_hval()");
	mu_run_test(test_digest_get_hval_ok);

	return 0;
}

int
main(void)
{
	tests_run = 0;

	char *result = all_tests();
	if (result != 0) {
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
