libdigest
=========

Libdigest is a small C library for parsing and generating HTTP Digest Access
Authentication ([rfc2617](https://www.ietf.org/rfc/rfc2617.txt)) header
strings, both server side and client side.

Only supports *qop="auth"* and *algorithm="MD5"* for now. If they are not supplied,
`auth` and `MD5` are assumed.

Please note that this library is under development and should not be used yet.

### To do, client

  * Parse qop according to rfc (could be a comma seperated list).
  * When rendering `Authorization` string, check for NULL values in struct.
  * When rendering `Authorization` string, take the `qop` value in
    consideration.
  * Better get/set functions for the attributes.

### To do, server

  * Start implementing it.

Build it
--------

    $ make && make install

How to use it
-------------

### Client side

First, include the header files:

```C
#include <digest.h>
#include <digest/client.h>
```

Create a new digest object with the value of the WWW-Authenticate header:

```C
digest_t d = digest_create("Digest realm=\"api\", qop=auth, nonce=dcd98b7102dd2f0e8b11d0f600bfb0c093");
```

Then supply the username, password and URI like below:

```C
digest_set_attr(d, D_ATTR_USERNAME, "jack");
digest_set_attr(d, D_ATTR_PASSWORD, "Pass0rd");
digest_set_attr(d, D_ATTR_URI, "/api/user");
digest_set_attr(d, D_ATTR_METHOD, "POST");
```

To get the string to use in the Authorization header, call ´digest_get_hval()´, as below:

```C
char *v = digest_get_hval(d);
```

All the code (compile with ´-ldigest´):

```C
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

	printf("Generated digest value:\n%s\n", v);

	return 0;
}
```
