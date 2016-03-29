#ifndef INC_DIGEST_HASH_H
#define INC_DIGEST_HASH_H

void hash_generate_a2(char *result, const char *method, const char *uri);
void hash_generate_a1(char *result, const char *username, const char *realm, const char *password);
void hash_generate_response_auth(char *result, const char *ha1, const char *nonce, unsigned int nc, unsigned int cnonce, const char *qop, const char *ha2);
void hash_generate_response(char *result, const char *ha1, const char *nonce, const char *ha2);

#endif  /* INC_DIGEST_HASH_H */
