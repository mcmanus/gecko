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
    q->SetTransmiter(inConfig->send_callback);
    q->SetReceiver(inConfig->recv_callback);
    q->SetHandShakeInput(inConfig->handshake_input);
    q->SetErrorCB(inConfig->error_callback);

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

MozQuic::MozQuic(bool handleIO)
  : mFD(-1)
  , mHandleIO(handleIO)
  , mIsClient(true)
  , mConnectionState(CLIENT_STATE_UNINITIALIZED)
  , mStream0Offset(0)
  , mLogCallback(nullptr)
  , mTransmitCallback(nullptr)
  , mReceiverCallback(nullptr)
  , mHandShakeInput(nullptr)
  , mErrorCB(nullptr)
  , mStream0Out(nullptr)
  , mStream0Allocation(nullptr)
  , mStream0OutAvail(0)
{
}

MozQuic::~MozQuic()
{
  if (mFD > 0) {
    close(mFD);
  }
  if (mStream0Allocation) {
    free (mStream0Allocation);
  }
}
  
int
MozQuic::StartConnection()
{
  assert(!mHandleIO); // todo

  if (mIsClient) {
    mConnectionState = CLIENT_STATE_1RTT;
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
    case CLIENT_STATE_1RTT:
      return Send1RTT();
      break;
    default:
      assert(false);
      // todo
    }

    switch (mConnectionState) {
    case CLIENT_STATE_1RTT:
      return Recv1RTT();
      break;
    default:
      assert(false);
      // todo
    }

  } else {
    assert(false);
    // todo
  }
  
  Log((char *)"todo IO()\n");
  return MOZQUIC_OK;
}

void
MozQuic::Log(char *msg) 
{
  // todo default mLogCallback can be dev/null
  if (mLogCallback) {
    mLogCallback(this, msg);
  } else {
    fprintf(stderr,"MozQuic Logger :%s:\n", msg);
  }
}

int
MozQuic::Recv(unsigned char *pkt, uint32_t avail, uint32_t &outLen)
{
  if (mReceiverCallback) {
    return mReceiverCallback(this, pkt, avail, &outLen);
  }
  ssize_t amt = recv(mFD, pkt, avail, 0);
  outLen = amt > 0 ? amt : 0;
  // todo errs

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

void
MozQuic::RaiseError(uint32_t e, char *reason)
{
  Log(reason);
  if (mErrorCB) {
    mErrorCB(this, e, reason);
  }
}

// this is called by the application when the application is handling
// the TLS stream (so that it can do more sophisticated handling
// of certs etc like gecko PSM does)
void
MozQuic::HandShakeOutput(unsigned char *buf, uint32_t datalen)
{
  // todo this is awful mvp stuff
  if (mStream0Out == mStream0Allocation) {
    // null case and totally unused case
    mStream0Allocation = (unsigned char *)realloc(mStream0Allocation, datalen + mStream0OutAvail);
    mStream0Out = mStream0Allocation;
  } else {
    unsigned char *newbuf = (unsigned char *) malloc(datalen + mStream0OutAvail);
    if (newbuf) {
      memcpy (newbuf, mStream0Out, mStream0OutAvail);
    }
    free (mStream0Allocation);
    mStream0Out = mStream0Allocation = newbuf;
  }

  if (mStream0Out) {
    memcpy (mStream0Out + mStream0OutAvail, buf, datalen);
    mStream0OutAvail += datalen;
  } else {
    RaiseError(MOZQUIC_ERR_MEMORY, (char *) "allocation err");
  }
}

void
MozQuic::GetHandShakeOutputData(unsigned char *p, uint16_t &outLen,
                                uint16_t available)
{
  assert(mHandShakeInput);
  outLen = mStream0OutAvail;
  if (!outLen) {
    return;
  }
  if (outLen > available) {
    outLen = available;
  }
  memcpy(p, mStream0Out, outLen);
  mStream0OutAvail -= outLen;
  mStream0Out += outLen;
  if (!mStream0OutAvail) {
    free (mStream0Allocation);
    mStream0Allocation = nullptr;
    mStream0Out = nullptr;
  }
}
  
int
MozQuic::Send1RTT() 
{
  unsigned char pkt[kMozQuicMTU];

  if (!mHandShakeInput) {
    // todo handle doing this internally
    assert(false);
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"need handshaker");
    return MOZQUIC_ERR_GENERAL;
  }

  // we need a client hello from nss up to
  // kMozQuicMTU - 17 (hdr) - 8 (stream header) - 8 (csum)
  uint16_t clientHelloLen = 0;
  GetHandShakeOutputData(pkt + 17 + 8, clientHelloLen,
                         kMozQuicMTU - 17 - 8 - 8);
  if (clientHelloLen < 1) {
    Log((char *)"Send1RTT has no data to send");
    return MOZQUIC_OK;
  }

  // section 5.4.1 of transport
  // long form header 17 bytes
  pkt[0] = 0x82;
  memcpy(pkt + 1, &mConnectionID, 8);
  memcpy(pkt + 9, &mNextPacketID, 4);
  memcpy(pkt + 13, &kMozQuicVersion, 4);

  if ((17 + 8 + 8 + clientHelloLen) > kMozQuicMTU) {
    // todo handle this as multiple packets
    assert(false);
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"client hello too big");
    return MOZQUIC_ERR_GENERAL;
  }

  // stream header is 8 bytes long
  // 1 type + 2 bytes of len, 1 stream id,
  // 4 bytes of offset. That's type 0xd8
  pkt[17] = 0xd8;
  uint16_t tmp = htons(clientHelloLen);
  memcpy(pkt + 18, &tmp, 2);
  pkt[20] = 0; // stream 0

  // 4 bytes of offset is normally a waste, but it just comes
  // out of padding
  pkt[21] = pkt[22] = pkt[23] = pkt[24] = mStream0Offset; // offset

  // clientHelloLen Bytes @ pkt + 17 + 8 are already full of data

  // then padding as needed up to 1272
  uint32_t paddingNeeded = kMozQuicMTU - 17 - 8 - 8 - clientHelloLen;
  memset (pkt + 17 + 8 + clientHelloLen, 0, paddingNeeded);

  // then 8 bytes of checksum on cleartext packets
  assert (FNV64size == 8);
  if (FNV64block(pkt, kMozQuicMTU - 8, pkt + kMozQuicMTU - 8) != 0) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"hash err");
    return MOZQUIC_ERR_GENERAL;
  }

  mStream0Offset += clientHelloLen;
  mNextPacketID++;
  Transmit(pkt, kMozQuicMTU);
  return MOZQUIC_OK;
}

int
MozQuic::ProcessServerCleartext(pkt, pktSize)
{
  // need retrans
  // connid from server
  // rand pkt #
  // stream, ack, padding
  // should ack
}

int
MozQuic::Recv1RTT() 
{
  if (!mHandShakeInput) {
    // todo handle doing this internally
    assert(false);
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"need handshaker");
    return MOZQUIC_ERR_GENERAL;
  }

  unsigned char pkt[kMozQuicMSS];
  uint32_t pktSize = 0;
  int code = Recv(pkt, kMozQuicMSS, pktSize);
  if (code != MOZQUIC_OK) {
    return code;
  }

  if (!pktSize) {
    Log((char *)"recv1rtt no packet");
    return MOZQUIC_OK;
  }
  Log((char *)"recv1rtt packet found");

  // the min packet is 9 bytes
  if (pktSize < 9) {
    Log((char *)"recv1rtt packet too short");
    return MOZQUIC_OK;
  }

  uint8_t type = pkt[0];
  type = (type & 0x80) ? (type & 0x7f) : (type & 0x1f);
  switch (type) {
  case 0x83: // Server Stateless Retry
    assert(false);
    // todo mvp
    break;
  case 0x84: // Server cleartext
    return ProcessServerCleartext(pkt, pktSize);
    break;
  case 0x84: // Client cleartext
    assert(false);
    // todo mvp
    break;
    
  default:
    Log((char *)"recv1rtt unexpected type");
    break;
  }
  return MOZ_QUIC_OK;
}

}}
