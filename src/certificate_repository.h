#pragma once
#include "error.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Opaque struct representing a certificate repository
 * to manage insertion of new certificates
 */
typedef struct certificate_repository certificate_repository;

/**
 * Certificate DTO
 */
typedef struct {
  /** Identifier for who generated the certificate */
  const char *entity;

  /** Creation time of the keypair in Unix seconds */
  uint64_t create_time_unix;

  /** Public key */
  const char *public_key;
} certificate;

/**
 * Creates a new repository for insertion of certificates
 *
 * \param connection connection string
 * \returns handle to the created repository on success, null otherwise
 */
certificate_repository *certificate_repository_new(const char *connection);

/**
 * Adds a certificate to the repository
 *
 * \param repo handle to certificate repository
 * \param cert cert DTO to add
 * \returns success on insertion, error otherwise
 */
error_code certificate_repository_add(certificate_repository *repo,
                                      certificate *cert);

/**
 * Destroys the repository freeing memory
 *
 * \param repo handle to certificate repository
 */
void certificate_repository_destroy(certificate_repository *repo);
