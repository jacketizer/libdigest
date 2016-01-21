#include <digest.h>
#include <digest/client.h>

int
main(int argc, char **argv)
{
  printf("Running test client for libdigest...\n");

  digest_t d = digest_create("Digest realm=\"api\", qop=auth, nonce=dcd98b7102dd2f0e8b11d0f600bfb0c093");
  digest_set_attr(d, D_ATTR_USERNAME, "jacket");
  digest_set_attr(d, D_ATTR_PASSWORD, "Pass0rd");
  digest_set_attr(d, D_ATTR_URI, "/api/user");
  digest_set_attr(d, D_ATTR_METHOD, "POST");
  char *v = digest_get_hval(d);

  printf("Digest Header Value: %s\n", v);

  return 0;
}
