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

    mozilla::net::MozQuic *q = new mozilla::net::MozQuic(inConfig->handleIO);
    if (!q) {
      return MOZQUIC_ERR_GENERAL;
    }
    *outConnection = (void *)q;

    q->SetLogger(inConfig->logging_callback);
    q->SetTransmiter(inConfig->transmit_callback);

//    connPtr->originName = strdup(inConfig->originName);
//    connPtr->originPort = inConfig->originPort;
    return MOZQUIC_OK;
  }

  int mozquic_destroy_connection(mozquic_connection_t *conn)
  {
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn));
    delete self;
    return MOZQUIC_OK;
  }

  int mozquic_start_connection(mozquic_connection_t *conn)
  {
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn));
    return self->StartConnection();
  }

  int mozquic_IO(mozquic_connection_t *conn)
  {
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn));
    return self->IO();
  }

  int mozquic_osfd(mozquic_connection_t *conn)
  {
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn));
    return self->GetFD();
  }

  void mozquic_setosfd(mozquic_connection_t *conn, int fd)
  {
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn));
    self->SetFD(fd);
  }

#ifdef __cplusplus
}
#endif

namespace mozilla { namespace net {

int
MozQuic::StartConnection()
{
  assert(!mHandleIO); // todo

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
    return mTransmitCallback(this, pkt, len);
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
  unsigned char clientHello[80];
  uint32_t clientHelloLen = 80;
  memset (clientHello, 0xbb, clientHelloLen);
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
