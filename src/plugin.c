#include "plugin.h"

#include <stdio.h>
#include <string.h>

#include "certificate_repository.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mqtt_protocol.h"
#include "utils.h"
#include <cbor.h>
#include <sodium.h>
#include <sys/time.h>

#define UNUSED(A) (void)(A)

static const char *ENTITY = "MOSQUITTO_MQTT_BROKER";

static mosquitto_plugin_id_t *mosq_pid = NULL;

static int error_code_to_mosquitto_error(error_code error) {
  switch (error) {
  case SUCCESS:
    return MOSQ_ERR_SUCCESS;
  case ERROR_INVALID_ARGUMENT:
    return MOSQ_ERR_INVAL;
  case ERROR_NO_MEMORY:
    return MOSQ_ERR_NOMEM;
  default:
    return MOSQ_ERR_UNKNOWN;
  }
}

/**
 * Initialize keypair in memory to sign messages,
 * and publish the public key to public storage for verification
 */
static int init_signing_keypair(plugin_config *config) {
  int error =
      crypto_sign_keypair(config->ca_public_key, config->ca_private_key);

  if (error) {
    mosquitto_log_printf(MOSQ_LOG_ERR,
                         "Failed to generate crypto sign keypair: %d", error);
    return error;
  }

  certificate_repository *cert_repo =
      certificate_repository_new(config->db_connection_string);
  if (cert_repo == NULL) {
    mosquitto_log_printf(MOSQ_LOG_ERR,
                         "Failed to create certificate repository");
    return -1;
  }

  char pk_hex_string[crypto_sign_PUBLICKEYBYTES * 2 + 1] = {0};
  sodium_bin2hex(pk_hex_string, sizeof(pk_hex_string), config->ca_public_key,
                 crypto_sign_PUBLICKEYBYTES);

  struct timeval tv;
  gettimeofday(&tv, NULL);

  certificate cert = {
      .entity = ENTITY,
      .create_time_unix = (uint64_t)tv.tv_sec,
      .public_key = pk_hex_string,
  };

  mosquitto_log_printf(MOSQ_LOG_DEBUG, "Generated keypair for entity %s at %lu",
                       ENTITY, cert.create_time_unix);

  error = certificate_repository_add(cert_repo, &cert);

  if (error) {
    mosquitto_log_printf(
        MOSQ_LOG_ERR, "Failed to add new certificate to repository: %d", error);
  }

  certificate_repository_destroy(cert_repo);
  return error;
}

static void load_configuration(plugin_config *config,
                               struct mosquitto_opt *opts, int opt_count) {
  for (size_t i = 0; i < opt_count; i++) {
    char *key = opts[i].key;
    char *value = opts[i].value;

    if (strcmp(key, "db_connection_string") == 0) {
      config->db_connection_string = value;
    } else {
      mosquitto_log_printf(MOSQ_LOG_WARNING,
                           "Unexpected configuration key (%s), ignoring it",
                           key);
    }
  }
}

static int callback_message(int event, void *event_data, void *userdata) {
  UNUSED(event);
  struct timeval tv;
  gettimeofday(&tv, NULL);

  plugin_config *config = (plugin_config *)userdata;
  struct mosquitto_evt_message *ed = (struct mosquitto_evt_message *)event_data;

  struct cbor_load_result load_result;
  cbor_item_t *cbor_map = cbor_load(ed->payload, ed->payloadlen, &load_result);

  if (load_result.error.code != CBOR_ERR_NONE) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading CBOR data: %d",
                         load_result.error.code);
    return -1;
  }

  if (!cbor_isa_map(cbor_map)) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "CBOR item is not a map");
    cbor_decref(&cbor_map);
    return -1;
  }

  if (!cbor_map_is_indefinite(cbor_map)) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "CBOR map is not indefinite");
    cbor_decref(&cbor_map);
    return -1;
  }

  cbor_item_t *ingestion_time_key = cbor_build_string("INGESTION_TIME");
  cbor_item_t *ingestion_time_value = cbor_build_uint64(tv.tv_usec / 1000u);
  struct cbor_pair ingestion_time_pair = {.key = ingestion_time_key,
                                          .value = ingestion_time_value};

  if (!cbor_map_add(cbor_map, ingestion_time_pair)) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to add INGESTION TIME");
    cbor_decref(&cbor_map);
    cbor_decref(&ingestion_time_key);
    cbor_decref(&ingestion_time_value);
    return -1;
  }

  error_code error = utils_make_signed_cbor_message(
      cbor_map, config->ca_private_key, "VERIFICATION_TOKEN");

  if (error != SUCCESS) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to make CBOR signed message %d",
                         error);
    cbor_decref(&cbor_map);
    return error_code_to_mosquitto_error(error);
  }

  // Serialize the updated CBOR map
  unsigned char *final_buffer = NULL;
  size_t final_size = 0;
  final_size = cbor_serialize_alloc(cbor_map, &final_buffer, &final_size);
  if (final_buffer == NULL) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to serialize updated CBOR map");
    cbor_decref(&cbor_map);
    return -1;
  }

  // Allocate output buffer using mosquitto_calloc
  uint8_t *new_payload = (uint8_t *)mosquitto_calloc(1, final_size);
  if (new_payload == NULL) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to allocate output buffer");
    cbor_decref(&cbor_map);
    free(final_buffer);
    return MOSQ_ERR_NOMEM;
  }

  // Copy the final serialized data to the output buffer
  memcpy(new_payload, final_buffer, final_size);

  /* Assign the new payload and payloadlen to the event data structure. You
   * must *not* free the original payload, it will be handled by the
   * broker. */
  ed->payload = new_payload;
  ed->payloadlen = final_size;

  cbor_decref(&cbor_map);
  free(final_buffer);
  return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_version(int supported_version_count,
                             const int *supported_versions) {
  int i;

  for (i = 0; i < supported_version_count; i++) {
    if (supported_versions[i] == 5) {
      return 5;
    }
  }

  return -1;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data,
                          struct mosquitto_opt *opts, int opt_count) {
  mosq_pid = identifier;

  if (sodium_init() == -1) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to initialize sodium");
    return MOSQ_ERR_UNKNOWN;
  }

  /* Init session data */
  *user_data = mosquitto_malloc(sizeof(plugin_config));
  if (*user_data == NULL) {
    mosquitto_log_printf(MOSQ_LOG_ERR,
                         "Failed to allocate memory for plugin config");
    return MOSQ_ERR_NOMEM;
  }

  plugin_config *config = (plugin_config *)*user_data;
  load_configuration(config, opts, opt_count);
  int error = init_signing_keypair(config);
  if (error) {
    return -1;
  }

  return mosquitto_callback_register(mosq_pid, MOSQ_EVT_MESSAGE,
                                     callback_message, NULL, config);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts,
                             int opt_count) {
  UNUSED(opts);
  UNUSED(opt_count);

  if (user_data != NULL) {
    mosquitto_free(user_data);
  }

  return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_MESSAGE,
                                       callback_message, NULL);
}