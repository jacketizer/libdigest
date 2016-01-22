#include <digest.h>
#include <digest/client.h>

int main(int argc, char **argv)
{
  char *digest_str = "Digest realm=\"api\", qop=auth, nonce=dcd98b7102dd2f0e8b11d0f600bfb0c093";
  printf("Generating header value for Authorization:\n%s\n", digest_str);

  digest_t d = digest_create(digest_str);
  digest_set_attr(d, D_ATTR_USERNAME, "jack");
  digest_set_attr(d, D_ATTR_PASSWORD, "Pass0rd");
  digest_set_attr(d, D_ATTR_URI, "/api/user");
  digest_set_attr(d, D_ATTR_METHOD, "POST");
  char *v = digest_get_hval(d);

  printf("Generated value:\n%s\n", v);

  return 0;
}
