#include "utils.h"
#include <cbor.h>
#include <sodium.h>
#include <string.h>
#include <time.h>

#define IS_NULL(x) ((x) == NULL)

error_code utils_make_signed_cbor_message(cbor_item_t *cbor_map,
                                          const uint8_t *private_key,
                                          const char *appended_signature_key) {

  unsigned char *serialized_map = NULL;
  size_t serialized_size = 0;
  unsigned char signature[crypto_sign_BYTES];
  cbor_item_t *signature_item = NULL;
  struct cbor_pair new_pair;

  if (IS_NULL(cbor_map) || IS_NULL(private_key) ||
      IS_NULL(appended_signature_key)) {
    return ERROR_INVALID_ARGUMENT;
  }

  if (!cbor_isa_map(cbor_map)) {
    return ERROR_INVALID_ARGUMENT;
  }

  // Serialize the CBOR map to prepare it for signing
  serialized_size =
      cbor_serialize_alloc(cbor_map, &serialized_map, &serialized_size);
  if (serialized_map == NULL) {
    return ERROR_NO_MEMORY;
  }

  if (crypto_sign_detached(signature, NULL, serialized_map, serialized_size,
                           private_key)) {
    free(serialized_map);
    return ERROR_UNKNOWN;
  }

  // Create a CBOR byte string for the signature
  signature_item = cbor_build_bytestring(signature, crypto_sign_BYTES);

  if (signature_item == NULL) {
    free(serialized_map);
    return ERROR_NO_MEMORY;
  }

  // Add the signature to the map
  new_pair.key = cbor_build_string(appended_signature_key);
  new_pair.value = signature_item;

  if (!cbor_map_add(cbor_map, new_pair)) {
    cbor_decref(&signature_item);
    free(serialized_map);
    return ERROR_UNKNOWN;
  }

  return SUCCESS;
}

void utils_timestamp_to_iso8601(uint64_t timestamp, char *buffer,
                                size_t buffer_size) {
  time_t raw_time = (time_t)timestamp;
  struct tm timeinfo;

  if (localtime_r(&raw_time, &timeinfo) == NULL) {
    snprintf(buffer, buffer_size, "Invalid timestamp");
    return;
  }

  if (strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%SZ", &timeinfo) == 0) {
    snprintf(buffer, buffer_size, "Formatting error");
    return;
  }
}