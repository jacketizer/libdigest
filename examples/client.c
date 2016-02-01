#include <stdio.h>
#include <digest.h>
#include <digest/client.h>

int main(int argc, char **argv)
{
	char *digest_str = "Digest realm=\"test\", qop=\"auth,auth-int\", nonce=\"9e9cb182c25b68148676a98cda86d501\"";
	printf("WWW-Authentication:\n%s\n", digest_str);

	if (-1 == digest_is_digest(digest_str)) {
		printf("Is not a digest string!\n");
		exit(1);
	}

	digest_t d = digest_create(digest_str);
	digest_set_attr(d, D_ATTR_USERNAME, "jack");
	digest_set_attr(d, D_ATTR_PASSWORD, "Pass0rd");
	digest_set_attr(d, D_ATTR_URI, "/api/test");
	digest_set_attr(d, D_ATTR_METHOD, DIGEST_METHOD_POST);
	char *v = digest_get_hval(d);

	printf("Authorization:\n%s\n", v);

	return 0;
}
