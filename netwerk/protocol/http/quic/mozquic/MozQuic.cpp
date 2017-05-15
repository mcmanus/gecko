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
#include "time.h"
#include "fnv.h"

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
    if (inConfig->domain == AF_INET) {
      connPtr->isV6 = 0;
//      memcpy(&connPtr->v4addr, inConfig->address, sizeof (struct sockaddr_in));
    } else {
      connPtr->isV6 = 1;
//      memcpy(&connPtr->v6addr, inConfig->address, sizeof (struct sockaddr_in6));
    }

    connPtr->q = new mozilla::net::MozQuic();
    connPtr->handleIO = inConfig->handleIO;
    assert(!inConfig->handleIO); // todo
    connPtr->q->SetLogger(inConfig->logging_callback);
    connPtr->q->SetTransmiter(inConfig->transmit_callback);

    connPtr->originName = strdup(inConfig->originName);
    connPtr->originPort = inConfig->originPort;
    return MOZQUIC_OK;
  }

  int mozquic_destroy_connection(mozquic_connection_t *inConnection)
  {
    if (!inConnection) {
      return MOZQUIC_ERR_INVALID;
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
    if (!conn || !conn->q) {
      return MOZQUIC_ERR_INVALID;
    }
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn->q));
    return self->GetFD();
  }

  void mozquic_setosfd(mozquic_connection_t *conn, int fd)
  {
    if (conn && conn->q) {
      mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn->q));
      self->SetFD(fd);
    }
  }

#ifdef __cplusplus
}
#endif

namespace mozilla { namespace net {

int
MozQuic::StartConnection()
{
  if (mIsClient) {
    mConnectionState = CLIENT_STATE_SEND_1RTT;
    // todo seed prng sensibly
    srandom(time(NULL));
    for (int i=0; i < 4; i++) {
      mConnectionID = mConnectionID << 16;
      mConnectionID = mConnectionID | (random() & 0xffff);
    }
    for (int i=0; i < 2; i++) {
      mNextPacketID = mNextPacketID << 16;
      mNextPacketID = mNextPacketID | (random() & 0xffff);
    }
  } else {
    assert(false);
    // todo
  }

  return MOZQUIC_OK;
}

int
MozQuic::IO()
{
  if (mIsClient) {
    switch (mConnectionState) {
    case CLIENT_STATE_SEND_1RTT:
      return Send1RTT();
      break;
    default:
      assert(false);
      // todo
    }
  } else {
    assert(false);
    // todo
  }
  
  fprintf(stderr,"todo IO()\n");
  return MOZQUIC_OK;
}

int
MozQuic::Transmit (unsigned char *pkt, uint32_t len)
{
  if (mTransmitCallback) {
    return mTransmitCallback(pkt, len);
  }
  send(mFD, pkt, len, 0); // todo errs
  return MOZQUIC_OK;
}

int
MozQuic::Send1RTT() 
{
  unsigned char pkt[kMozQuicMTU];

  // section 5.4.1 of transport
  // long form header 17 bytes
  pkt[0] = 0x82;
  memcpy(pkt + 1, &mConnectionID, 8);
  memcpy(pkt + 9, &mNextPacketID, 4);
  memcpy(pkt + 13, &kMozQuicVersion, 4);
  mNextPacketID++;

  // we need a client hello from nss up to
  // kMozQuicMTU - 17 (hdr) - 1 (stream type) - 8 (csum

  // stream frame type byte is 0xd0 and header is
  // 2 bytes of len, 0x00 (stream 0), then
  // len bytes of data
  pkt[17] = 0xd;
  memcpy (pkt + 18, clientHello, clientHelloLen);

  // then padding as needed up to 1272
  uint32_t paddingNeeded = kMozQuicMTU - 17 - 1 - 8 - clientHelloLen;
  memset (pkt + 17 + 1 + clientHelloLen, 0, paddingNeeded);

  // then 8 bytes of checksum on cleartext packets
  assert (FNV64size == 8);
  if (FNV64block(pkt, kMozQuicMTU - 8, pkt + kMozQuicMTU - 8) != 0) {
    // todo log
    return MOZQUIC_ERR_GENERAL;
  }

  Transmit(pkt, kMozQuicMTU);
  return MOZQUIC_OK;
}


}}
