#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include <cmocka.h>

#include <cbor.h>
#include <sodium.h>

#include "utils.h"

// Mock private key for testing (normally you'd load this securely)
static unsigned char test_private_key[crypto_sign_SECRETKEYBYTES];
static unsigned char test_public_key[crypto_sign_PUBLICKEYBYTES];

// Helper function to initialize libsodium and generate a test key pair
static void initialize_test_keys(void) {
  if (sodium_init() == -1) {
    fail_msg("Failed to initialize libsodium");
  }

  crypto_sign_keypair(test_public_key, test_private_key);
}

// Test when all arguments are valid
static void test_utils_make_signed_cbor_message_success(void **state) {
  (void)state; // Unused

  initialize_test_keys();

  // Create a sample CBOR map
  cbor_item_t *map = cbor_new_indefinite_map();
  cbor_map_add(map,
               (struct cbor_pair){.key = cbor_build_string("message"),
                                  .value = cbor_build_string("Hello, World!")});

  error_code result = utils_make_signed_cbor_message(
      map, (const char *)test_private_key, "signature");

  assert_int_equal(result, SUCCESS);

  // Verify that the signature was added to the map
  size_t map_size = cbor_map_size(map);
  assert_int_equal(map_size, 2);

  // Check that the "signature" key exists
  cbor_item_t *signature_value = NULL;
  for (size_t i = 0; i < map_size; i++) {
    struct cbor_pair pair = cbor_map_handle(map)[i];
    if (cbor_isa_string(pair.key)) {
      char *key_str = (char *)cbor_string_handle(pair.key);
      if (strcmp(key_str, "signature") == 0) {
        signature_value = pair.value;
        break;
      }
    }
  }

  assert_non_null(signature_value);
  assert_true(cbor_isa_bytestring(signature_value));

  // Clean up
  cbor_decref(&map);
}

// Test when cbor_map is NULL
static void test_utils_make_signed_cbor_message_null_cbor_map(void **state) {
  (void)state; // Unused

  initialize_test_keys();

  error_code result = utils_make_signed_cbor_message(
      NULL, (const char *)test_private_key, "signature");

  assert_int_equal(result, ERROR_INVALID_ARGUMENT);
}

// Test when private_key is NULL
static void test_utils_make_signed_cbor_message_null_private_key(void **state) {
  (void)state; // Unused

  // Create a sample CBOR map
  cbor_item_t *map = cbor_new_definite_map(1);
  cbor_map_add(map,
               (struct cbor_pair){.key = cbor_build_string("message"),
                                  .value = cbor_build_string("Hello, World!")});

  error_code result = utils_make_signed_cbor_message(map, NULL, "signature");

  assert_int_equal(result, ERROR_INVALID_ARGUMENT);

  // Clean up
  cbor_decref(&map);
}

// Test when appended_signature_key is NULL
static void
test_utils_make_signed_cbor_message_null_signature_key(void **state) {
  (void)state; // Unused

  initialize_test_keys();

  // Create a sample CBOR map
  cbor_item_t *map = cbor_new_definite_map(1);
  cbor_map_add(map,
               (struct cbor_pair){.key = cbor_build_string("message"),
                                  .value = cbor_build_string("Hello, World!")});

  error_code result =
      utils_make_signed_cbor_message(map, (const char *)test_private_key, NULL);

  assert_int_equal(result, ERROR_INVALID_ARGUMENT);

  // Clean up
  cbor_decref(&map);
}

// Test when cbor_map is not a map (e.g., it's a string)
static void
test_utils_make_signed_cbor_message_invalid_cbor_type(void **state) {
  (void)state; // Unused

  initialize_test_keys();

  // Create a CBOR string instead of a map
  cbor_item_t *str_item = cbor_build_string("Not a map");

  error_code result = utils_make_signed_cbor_message(
      str_item, (const char *)test_private_key, "signature");

  assert_int_equal(result, ERROR_INVALID_ARGUMENT);

  // Clean up
  cbor_decref(&str_item);
}

// Test signature correctness
static void
test_utils_make_signed_cbor_message_signature_correctness(void **state) {
  (void)state; // Unused

  initialize_test_keys();

  // Create a sample CBOR map
  cbor_item_t *map = cbor_new_indefinite_map();
  cbor_map_add(map,
               (struct cbor_pair){.key = cbor_build_string("message"),
                                  .value = cbor_build_string("Test Message")});

  // Serialize the map before signing
  unsigned char *sermap = NULL;
  size_t serialized_size = 0;
  serialized_size = cbor_serialize_alloc(map, &sermap, &serialized_size);

  error_code result =
      utils_make_signed_cbor_message(map, test_private_key, "signature");
  assert_int_equal(result, SUCCESS);

  // Find the signature in the map
  cbor_item_t *signature_value = NULL;
  size_t map_size = cbor_map_size(map);
  for (size_t i = 0; i < map_size; i++) {
    struct cbor_pair pair = cbor_map_handle(map)[i];
    if (cbor_isa_string(pair.key)) {
      char *key_str = (char *)cbor_string_handle(pair.key);
      if (strcmp(key_str, "signature") == 0) {
        signature_value = pair.value;
        break;
      }
    }
  }

  assert_non_null(signature_value);
  assert_true(cbor_isa_bytestring(signature_value));

  // Verify the signature
  unsigned char *signature = cbor_bytestring_handle(signature_value);
  size_t signature_size = cbor_bytestring_length(signature_value);

  assert_int_equal(signature_size, crypto_sign_BYTES);

  int verify_result = crypto_sign_verify_detached(
      signature, sermap, serialized_size, test_public_key);

  assert_int_equal(verify_result, 0); // 0 indicates success

  // Clean up
  cbor_decref(&map);
  free(sermap);
}

static void test_utils_iso_timestamp(void **state) {
  uint64_t unix_seconds = 1733393632;
  char iso_string[64];
  utils_timestamp_to_iso8601(unix_seconds, iso_string, sizeof(iso_string));
  assert_string_equal(iso_string, "2024-12-05T11:13:52Z");
}

// Main function to run tests
int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_utils_make_signed_cbor_message_success),
      cmocka_unit_test(test_utils_make_signed_cbor_message_null_cbor_map),
      cmocka_unit_test(test_utils_make_signed_cbor_message_null_private_key),
      cmocka_unit_test(test_utils_make_signed_cbor_message_null_signature_key),
      cmocka_unit_test(test_utils_make_signed_cbor_message_invalid_cbor_type),
      cmocka_unit_test(
          test_utils_make_signed_cbor_message_signature_correctness),
      cmocka_unit_test(test_utils_iso_timestamp),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
