#include "certificate_repository.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "utils.h"
#include <assert.h>
#include <postgresql/libpq-fe.h>
#include <stdlib.h>

static const char *QUERY_CREATE_TABLE =
    "CREATE TABLE IF NOT EXISTS \"entity_certificates\" ( \
                entity      text                                    not null, \
                create_time timestamp with time zone                not null, \
                public_key  text                                    not null  \
            );";

static const char *QUERY_INSERT_CERTIFICATE =
    "INSERT INTO \"entity_certificates\" (entity, create_time, public_key) "
    "VALUES ($1, $2, $3)";

struct certificate_repository {
  PGconn *connection;
};

certificate_repository *certificate_repository_new(const char *connection) {
  assert(connection != NULL);

  certificate_repository *repo =
      (certificate_repository *)calloc(1, sizeof(certificate_repository));

  repo->connection = PQconnectdb(connection);
  if (repo->connection == NULL) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to create new connnection");
    free(repo);
    return NULL;
  }

  if (PQstatus(repo->connection) != CONNECTION_OK) {
    mosquitto_log_printf(MOSQ_LOG_ERR,
                         "Failed to enstablish new connection, reason: %s",
                         PQerrorMessage(repo->connection));
    certificate_repository_destroy(repo);
    return NULL;
  }

  PGresult *query_create_table_result =
      PQexec(repo->connection, QUERY_CREATE_TABLE);

  ExecStatusType status = PQresultStatus(query_create_table_result);

  if (status != PGRES_COMMAND_OK) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to create tables, reason: %s",
                         PQerrorMessage(repo->connection));
    PQclear(query_create_table_result);
    certificate_repository_destroy(repo);
    return NULL;
  }

  return repo;
}

error_code certificate_repository_add(certificate_repository *repo,
                                      certificate *cert) {

  assert(repo != NULL);
  assert(cert != NULL);

  char isotime[64] = {0};
  utils_timestamp_to_iso8601(cert->create_time_unix, isotime, sizeof(isotime));

  const char *values[] = {cert->entity, isotime, cert->public_key};

  PGresult *result =
      PQexecParams(repo->connection, QUERY_INSERT_CERTIFICATE,
                   3,      // Number of parameters
                   NULL,   // Parameter types (NULL means automatic inference)
                   values, // Parameter values
                   NULL,   // Parameter lengths (NULL means strings)
                   NULL,   // Parameter formats (NULL means text)
                   0       // Result format (0 means text)
      );

  ExecStatusType status = PQresultStatus(result);

  if (status != PGRES_COMMAND_OK) {
    mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to insert certificate: %s",
                         PQerrorMessage(repo->connection));
    PQclear(result);
    return ERROR_UNKNOWN;
  }

  return SUCCESS;
}

void certificate_repository_destroy(certificate_repository *repo) {
  assert(repo != NULL);
  PQfinish(repo->connection);
  free(repo);
}
