#pragma once
#include "error.h"
#include <cbor.h>
#include <stddef.h>

/**
 * Makes a serialized CBOR message with an additional key that contains
 * the ED25519 signature of the message. This method allocates memory.
 * This method expects that the passed cbor_buffer contains a map type value.
 *
 * \param map CBOR item on which the signature will be calculated and appended
 * \param private_key key used to sign the payload with ED25519 algorithm
 * \param appended_signature_key key value for the signature that will be
 * appended
 * \returns a error code
 */
error_code utils_make_signed_cbor_message(cbor_item_t *map,
                                          const uint8_t *private_key,
                                          const char *appended_signature_key);

/**
 * Converts unix timestamp (in seconds) into ISO8601 string
 *
 * \param timestamp unix seconds
 * \param buffer out buffer for the ISO8601 string
 * \param buffer_size size of the buffer
 */
void utils_timestamp_to_iso8601(uint64_t timestamp, char *buffer,
                                size_t buffer_size);
