libdigest
=========

[![Build Status](https://travis-ci.org/jacketizer/libdigest.svg?branch=master)](https://travis-ci.org/jacketizer/libdigest)

Libdigest is a small C library for parsing and generating HTTP Digest Access
Authentication ([rfc2617](https://www.ietf.org/rfc/rfc2617.txt)) header
strings, both server side and client side.

Only supports *qop="auth"* and *algorithm="MD5"* for now. If they are not supplied,
`auth` and `MD5` are assumed.

Please note that this library is under development and should not be used yet.

### To do, client

  * When to increase `nc`.
  * Better get/set functions for the attributes.
  * Unit tests.
  * Function documentation.
  * Function tests.

### To do, server

  * Start implementing it.

Build it
--------

```sh
$ make && make install
```

How to use it
-------------

### Client side

First, include the header files:

```C
#include <stdio.h>
#include <digest.h>
#include <digest/client.h>
```

Create a new digest object with the value of the `WWW-Authenticate` header:

```C
digest_t d;
digest_parse(&d, "Digest realm=\"api\", qop=\"auth,auth-int\", nonce=dcd98b7102dd2f0e8b11d0f600bfb0c093");
```

Then supply the username, password, URI and HTTP method like below:

```C
digest_set_attr(&d, D_ATTR_USERNAME, "jack");
digest_set_attr(&d, D_ATTR_PASSWORD, "Passw0rd");
digest_set_attr(&d, D_ATTR_URI, "/api/test");
digest_set_attr(&d, D_ATTR_METHOD, DIGEST_METHOD_POST);
```

To generate the string to use in the `Authorization` header, call `digest_get_hval()`, as below:

```C
char result[1024];
digest_get_hval(&d, result, sizeof (result));
```

All the code (compile with `-ldigest`):

```C
#include <stdio.h>
#include <digest.h>
#include <digest/client.h>

int
main(int argc, char **argv)
{
	digest_t d;
	char result[1024];
	char digest_str[] = "Digest realm=\"api\", qop=\"auth-int,auth\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";
	printf("WWW-Authentication: %s\n", digest_str);

	digest_parse(&d, digest_str);
	digest_set_attr(&d, D_ATTR_USERNAME, "jack");
	digest_set_attr(&d, D_ATTR_PASSWORD, "Pass0rd");
	digest_set_attr(&d, D_ATTR_URI, "/api/user");
	digest_set_attr(&d, D_ATTR_METHOD, DIGEST_METHOD_POST);

	digest_get_hval(&d, result, sizeof (result));
	printf("Authorization: %s\n", result);

	return 0;
}
```

Attributes
----------

| Attribute            | Data Type | Header Attr         | Default                | Mandatory |
|:---------------------|:----------|:--------------------|:-----------------------|:----------|
| `D_ATTR_USERNAME`    | `char *`  | `username`          | `NULL`                 | Yes       |
| `D_ATTR_PASSWORD`    | `char *`  | `response` (hashed) | `NULL`                 | Yes       |
| `D_ATTR_REALM`       | `char *`  | `realm`             | Parsed value           |           |
| `D_ATTR_NONCE`       | `char *`  | `nonce`             | Parsed value           |           |
| `D_ATTR_CNONCE`      | `int`     | `cnonce`            | Random value           |           |
| `D_ATTR_OPAQUE`      | `char *`  | `opaque`            | Parsed value           |           |
| `D_ATTR_URI`         | `char *`  | `uri`               | `NULL`                 | Yes       |
| `D_ATTR_METHOD`      | `int`     | `response` (hashed) |                        | Yes       |
| `D_ATTR_ALGORITHM`   | `int`     | `algorithm`         | `DIGEST_ALGORITHM_MD5` |           |
| `D_ATTR_QOP`         | `int`     | `qop`               | `auth`                 |           |
| `D_ATTR_NONCE_COUNT` | `int`     | `nc`                | 1                      |           |
