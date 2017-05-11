/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "MozQuic.h"
#include "MozQuicInternal.h"

#include "assert.h"
#include "netinet/ip.h"
#include "stdlib.h"
#include "unistd.h"

#ifdef __cplusplus
extern "C" {
#endif

  int mozquic_new_connection(mozquic_connection_t **outConnection,
                             mozquic_config_t *inConfig)
  {
    mozquic_connection_t *connPtr = NULL;

    if (!outConnection || !inConfig) {
      return MOZQUIC_ERR_INVALID;
    }

    if (!inConfig->originName) {
      return MOZQUIC_ERR_INVALID;
    }

    if ((inConfig->domain != AF_INET) &&
        (inConfig->domain != AF_INET6)) {
      return MOZQUIC_ERR_INVALID;
    }

    *outConnection = (mozquic_connection_t *) malloc (sizeof (mozquic_connection_t));
    if (!*outConnection) {
      return MOZQUIC_ERR_GENERAL;
    }

    connPtr = *outConnection;
    memset(connPtr, 0, sizeof(mozquic_connection_t));
    connPtr->q = new mozilla::net::MozQuic();
    connPtr->handleIO = inConfig->handleIO;
    assert(!inConfig->handleIO); // todo
    if (inConfig->domain == AF_INET) {
      connPtr->isV6 = 0;
//      memcpy(&connPtr->v4addr, inConfig->address, sizeof (struct sockaddr_in));
    } else {
      connPtr->isV6 = 1;
//      memcpy(&connPtr->v6addr, inConfig->address, sizeof (struct sockaddr_in6));
    }
    connPtr->originName = strdup(inConfig->originName);
    connPtr->originPort = inConfig->originPort;
    connPtr->udp = socket(inConfig->domain, SOCK_DGRAM, 0);
    return MOZQUIC_OK;
  }

  int mozquic_destroy_connection(mozquic_connection_t *inConnection)
  {
    if (!inConnection) {
      return MOZQUIC_ERR_INVALID;
    }
    if (inConnection->udp > 0) {
      close(inConnection->udp);
    }
    if (inConnection->originName) {
      free(inConnection->originName);
    }
    delete (inConnection->q);
    memset(inConnection, 0, sizeof(mozquic_connection_t));

    return MOZQUIC_OK;
  }

  int mozquic_start_connection(mozquic_connection_t *conn)
  {
    if (!conn) {
      return MOZQUIC_ERR_INVALID;
    }
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn->q));
    return self->StartConnection();
  }

  int mozquic_IO(mozquic_connection_t *conn)
  {
    if (!conn) {
      return MOZQUIC_ERR_INVALID;
    }
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn->q));
    return self->IO();
  }

  int mozquic_osfd(mozquic_connection_t *conn)
  {
    if (!conn) {
      return MOZQUIC_ERR_INVALID;
    }
    return conn->udp;
  }

  void mozquic_setosfd(mozquic_connection_t *conn, int fd)
  {
    if (conn) {
      conn->udp = fd;
    }
  }

#ifdef __cplusplus
}
#endif

namespace mozilla { namespace net {

int
MozQuic::StartConnection()
{
  fprintf(stderr, "DID IT2\n\n\n\n");
  return MOZQUIC_OK;
}

int
MozQuic::IO()
{
  fprintf(stderr,"todo IO()\n");
  return MOZQUIC_OK;
}

}}
