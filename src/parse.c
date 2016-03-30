#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "digest.h"
#include "parse.h"

/**
 * Extracts the value part from a attribute-value pair.
 *
 * parameter is the string to parse the value from, ex: "key=value".
 *           The string needs to be null-terminated. Can be both
 *           key=value and key="value".
 *
 * Returns a pointer to the start of the value on success, otherwise NULL.
 */
static char *
_dgst_get_val(char *parameter)
{
	char *cursor, *q;

	/* Find start of value */
	if (NULL == (cursor = strchr(parameter, '='))) {
		return (char *) NULL;
	}

	if (*(++cursor) != '"') {
		return cursor;
	}

	cursor++;
	if (NULL == (q = strchr(cursor, '"'))) {
		return (char *) NULL;
	}
	*q = '\0';

	return cursor;
}

/**
 * Checks if a string pointer is NULL or if the length is more than 255 chars.
 *
 * string is the string to check.
 *
 * Returns 0 if not NULL and length is below 256 characters, otherwise -1.
 */
int
_check_string(const char *string)
{
	if (NULL == string || 255 < strlen(string)) {
		return -1;
	}

	return 0;
}

/**
 * Removes the authentication scheme identification token from the
 * WWW-Authenticate header field value.
 *
 * header_value is the WWW-Authenticate header field value.
 *
 * Returns a pointer to a new string containing only
 * the authentication parameters. Must be free'd manually.
 */
static char *
_crop_sentence(const char *header_value)
{
 	/* Skip Digest word, and duplicate string */
	return strdup(header_value + 7);
}

/**
 * Splits a string by comma.
 *
 * sentence is the string to split, null terminated.
 * values is a char pointer array that will be filled with pointers to the
 * splitted values in the sentence string.
 * max_values is the length of the **values array. The function will not parse
 * more than max_values entries.
 *
 * Returns the number of values found in string.
 */
static inline int
_split_string_by_comma(char *sentence, char **values, int max_values)
{
	int i = 0;

	while (i < max_values && '\0' != *sentence) {
		/* Rewind to after spaces */
		while (' ' == *sentence || ',' == *sentence) {
			sentence++;
		}

		/* Check for end of string */
		if ('\0' == *sentence) {
			break;
		}

		values[i++] = sentence;

		/* Find comma */
		if (NULL == (sentence = strchr(sentence, ','))) {
			/* End of string */
			break;
		}

		*(sentence++) = '\0';
	}

	return i;
}

/**
 * Tokenizes a string containing comma-seperated attribute-key parameters.
 *
 * sentence is the string to split, null terminated.
 * values is a char pointer array that will be filled with pointers to the
 * splitted values in the sentence string.
 * max_values is the length of the **values array. The function will not parse
 * more than max_values entries.
 *
 * Returns the number of values found in sentence.
 */
static inline unsigned int
_tokenize_sentence(char *sentence, char **values, unsigned int max_values)
{
	unsigned int i = 0;
	char *cursor = sentence;

	while (i < max_values && *cursor != '\0') {
		/* Rewind to after spaces */
		while (' ' == *cursor || ',' == *cursor) {
			cursor++;
		}

		/* Check for end of string */
		if ('\0' == *cursor) {
			break;
		}

		values[i++] = cursor;

		/* Find equal sign (=) */
		if (NULL == (cursor = strchr(cursor, '='))) {
			/* End of string */
			break;
		}

		/* Check if a quotation mark follows the = */
		if ('\"' == *(++cursor)) {
			/* Find next quotation mark */
			if (NULL == (cursor = strchr(++cursor, '\"'))) {
				/* End of string */
				break;
			}
			/* Comma should be after */
			cursor++;
		} else {
			/* Find comma */
			if (NULL == (cursor = strchr(cursor, ','))) {
				/* End of string */
				break;
			}
		}

		*(cursor++) = '\0';
	}

	return i;
}

/**
 * Parses a WWW-Authenticate header value to a struct.
 *
 * dig is a pointer to the digest struct to fill the parsed values with.
 * digest_string should be the value from the WWW-Authentication header,
 * null terminated.
 *
 * Returns the hash as a null terminated string. Should be free'd manually.
 */
int
parse_digest(digest_s *dig, const char *digest_string)
{
	int n, i = 0;
	char *val, *parameters;
	char *values[12];

	parameters = _crop_sentence(digest_string);
	n = _tokenize_sentence(parameters, values, ARRAY_LENGTH(values));

	while (i < n) {
		if (NULL == (val = values[i++])) {
			continue;
		}

		if (0 == strncmp("nonce=", val, strlen("nonce="))) {
			dig->nonce = _dgst_get_val(val);
		} else if (0 == strncmp("realm=", val, strlen("realm="))) {
			dig->realm = _dgst_get_val(val);
		} else if (0 == strncmp("qop=", val, strlen("qop="))) {
			char *qop_options = _dgst_get_val(val);
			char *qop_values[2];
			int n_qops = _split_string_by_comma(qop_options, qop_values, ARRAY_LENGTH(qop_values));
			while (n_qops-- > 0) {
				if (0 == strncmp(qop_values[n_qops], "auth", strlen("auth"))) {
					dig->qop |= DIGEST_QOP_AUTH;
					continue;
				}
				if (0 == strncmp(qop_values[n_qops], "auth-int", strlen("auth-int"))) {
					dig->qop |= DIGEST_QOP_AUTH_INT;
				}
			}
		} else if (0 == strncmp("opaque=", val, strlen("opaque="))) {
			dig->opaque = _dgst_get_val(val);
		} else if (0 == strncmp("algorithm=", val, strlen("algorithm="))) {
			char *algorithm = _dgst_get_val(val);
			if (0 == strncmp(algorithm, "MD5", strlen("MD5"))) {
				dig->algorithm = DIGEST_ALGORITHM_MD5;
			}
		}
	}

	return i;
}

/**
 * Validates the string values in a digest struct.
 *
 * The function goes through the string values and check if they are valid.
 * They are considered valid if they aren't NULL and the character length is
 * below 256.
 *
 * dig is a pointer to the struct where to check the string values.
 *
 * Returns 0 if valid, otherwise -1.
 */
int
parse_validate_attributes(digest_s *dig)
{
	if (-1 == _check_string(dig->username)) {
		return -1;
	}
	if (-1 == _check_string(dig->password)) {
		return -1;
	}
	if (-1 == _check_string(dig->uri)) {
		return -1;
	}
	if (-1 == _check_string(dig->realm)) {
		return -1;
	}
	if (NULL != dig->opaque && 255 < strlen(dig->opaque)) {
		return -1;
	}

	/* nonce */
	if (DIGEST_QOP_NOT_SET != dig->qop && -1 == _check_string(dig->nonce)) {
		return -1;
	}

	return 0;
}
