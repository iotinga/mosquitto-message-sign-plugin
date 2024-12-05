#pragma once
#include <stdint.h>

typedef struct {
  const char *db_connection_string;
  uint8_t ca_public_key[32];
  uint8_t ca_private_key[64];
} plugin_config;