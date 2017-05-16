/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "MozQuicStream.h"

#include "assert.h"
#include "netinet/ip.h"
#include "stdlib.h"
#include "unistd.h"
#include "time.h"
#include "fnv.h"
#include "sys/time.h"

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
  , mVersion(kMozQuicVersion1)
  , mLogCallback(nullptr)
  , mTransmitCallback(nullptr)
  , mReceiverCallback(nullptr)
  , mHandShakeInput(nullptr)
  , mErrorCB(nullptr)
  , mStream0(new MozQuicStreamPair(0, this))
{
}

MozQuic::~MozQuic()
{
  if (mFD > 0) {
    close(mFD);
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

uint32_t
MozQuic::Intake()
{
  // check state
  assert (mConnectionState == CLIENT_STATE_1RTT); // todo mvp

  unsigned char pkt[kMozQuicMSS];
  do {
    uint32_t pktSize = 0;
    int code = Recv(pkt, kMozQuicMSS, pktSize);
    // todo 17 assumes long form
    if (code != MOZQUIC_OK || !pktSize || pktSize < 17) {
      return code;
    }
    Log((char *)"intake found");

    if (!(pkt[0] & 0x80)) {
      // short form header when we only expect long form
      // cleartext
      Log((char *)"short form header at wrong time");
      continue;
    }

    uint8_t type = pkt[0] & 0x7f;
    switch (type) {
    case 0x01: // version negotiation
      assert(false);
      // todo mvp
      break;
    case 0x03: // Server Stateless Retry
      assert(false);
      // todo mvp
      break;
    case 0x04: // Server cleartext
      ProcessServerCleartext(pkt, pktSize);
      break;
    case 0x05: // Client cleartext
      assert(false);
      // todo mvp
      break;

    default:
      // reject anything that is nto a cleartext packet (not right, but later)
      Log((char *)"recv1rtt unexpected type");
      // todo this could actually be protected packet
      // and ideally would be queued. for now we rely on retrans
      break;
    }
  } while (1);

  return MOZQUIC_OK;
}

int
MozQuic::IO()
{
  Intake();
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

uint32_t
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

uint32_t
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
  mStream0->Write(buf, datalen);
}

int
MozQuic::Send1RTT() 
{
  if (!mHandShakeInput) {
    // todo handle doing this internally
    assert(false);
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"need handshaker");
    return MOZQUIC_ERR_GENERAL;
  }

  Flush();
  return MOZQUIC_OK;
}

int
MozQuic::ProcessServerCleartext(unsigned char *pkt, uint32_t pktSize)
{
  // received a 0x84 packet
  // cleartext is always in long form
  assert(pkt[0] & 0x80);
  assert(pkt[0] == 0x84);
  assert(pktSize >= 17);

  uint32_t pktNum;
  memcpy(&pktNum, pkt + 9, 4);
  pktNum = ntohl(pktNum);
  uint32_t version;
  memcpy(&version, pkt + 13, 4);
  version = ntohl(version);
  if (version != mVersion) {
    Log((char *)"wrong version");
    return MOZQUIC_ERR_GENERAL;
    // this should not abort session as its
    // not authenticated
  }
  
  memcpy(&mConnectionID, pkt + 1, 8);
  // todo log change

  
  unsigned char *framePtr = pkt + 17;
  unsigned char *endPtr = pkt + pktSize;

  while (framePtr < endPtr) {
    unsigned char type = framePtr[0];
    if (type == FRAME_TYPE_PADDING) {
      framePtr++;
      continue;
    } else if ((type & FRAME_MASK_STREAM) == FRAME_MASK_STREAM_RESULT) {
      bool finBit = (type & 0x20);
      bool lenBit = (type & 0x10);

      uint32_t lenLen = lenBit ? 2 : 0;
      uint32_t offsetLen = (type & 0x0c) >> 2;
      if (offsetLen == 1) {
        offsetLen = 2;
      } else if (offsetLen == 2) {
        offsetLen = 4;
      } else if (offsetLen == 3) {
        offsetLen = 8;
      }

      uint32_t idLen = (type & 0x03) + 1;
      uint32_t bytesNeeded = 1 + lenLen + idLen + offsetLen;
      if (framePtr + bytesNeeded > endPtr) {
        RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream frame header short");
        return MOZQUIC_ERR_GENERAL;
      }
      uint16_t dataLen;
      if (lenBit) {
        memcpy (&dataLen, framePtr + 1, 2);
        dataLen = ntohs(dataLen);
      } else {
        dataLen = endPtr - (framePtr + bytesNeeded);
      }
      
      // todo log frame len
      bytesNeeded += dataLen;
      if (framePtr + bytesNeeded > endPtr) {
        RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream frame data short");
        return MOZQUIC_ERR_GENERAL;
      }
      framePtr += 1 + lenLen;
      uint32_t streamID = 0;
      memcpy(&streamID + (4 - idLen), framePtr, idLen);
      framePtr += idLen;
      streamID = ntohl(streamID);
      if (streamID != 0) {
        RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream 0 expected");
        return MOZQUIC_ERR_GENERAL;
      }

      uint64_t offset = 0;
      memcpy(&offset + (8 - offsetLen), framePtr, offsetLen);
      framePtr += offsetLen;
      offset = ntohll(offset);

      std::unique_ptr<MozQuicStreamChunk>
        tmp(new MozQuicStreamChunk(streamID, offset, framePtr, dataLen, finBit));
      mStream0->Supply(tmp);
      framePtr += dataLen;
      // todo mvp generate ACK
    } else if ((type & FRAME_MASK_ACK) == FRAME_MASK_ACK_RESULT) {
      assert(false);
      // todo mvp process ack
    } else {
      RaiseError(MOZQUIC_ERR_GENERAL, (char *) "unexpected frame type");
      return MOZQUIC_ERR_GENERAL;
    }
  }
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
    // meara is great!
    break;
  case 0x84: // Server cleartext
    return ProcessServerCleartext(pkt, pktSize);
    break;
  case 0x85: // Client cleartext
    assert(false);
    // todo mvp
    break;
    
  default:
    Log((char *)"recv1rtt unexpected type");
    break;
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuic::FlushStream0()
{
  unsigned char pkt[kMozQuicMTU];
  uint32_t tmp32; // todo check range
  assert (mConnectionState == CLIENT_STATE_1RTT);

  // section 5.4.1 of transport
  // long form header 17 bytes
  pkt[0] = 0x82;
  memcpy(pkt + 1, &mConnectionID, 8);
  tmp32 = htonl(mNextPacketID);
  memcpy(pkt + 9, &tmp32, 4);
  tmp32 = htonl(mVersion);
  memcpy(pkt + 13, &tmp32, 4);

  uint32_t room = kMozQuicMTU - 17 - 8; // long form + csum
  unsigned char *framePtr = pkt + 17;
  
  std::list<std::unique_ptr<MozQuicStreamChunk>>::iterator iter;
  iter = mUnWritten.begin();
  while (iter != mUnWritten.end()) {
    if ((*iter)->mStreamID == 0) {
      if (room < (*iter)->mLen + 8) {
        break;
      }

      // stream header is 8 bytes long
      // 1 type + 2 bytes of len, 1 stream id,
      // 4 bytes of offset. That's type 0xd8
      framePtr[0] = 0xd8;
      uint16_t tmp16 = (*iter)->mLen;
      // todo check range
      tmp16 = htons(tmp16);
      memcpy(framePtr + 1, &tmp16, 2);
      framePtr[3] = 0; // stream 0

      // 4 bytes of offset is normally a waste, but it just comes
      // out of padding
      tmp32 = (*iter)->mOffset;
      tmp32 = htonl(tmp32);
      memcpy(framePtr + 4, &tmp32, 4);
      memcpy(framePtr + 8, (*iter)->mData.get(), (*iter)->mLen);
      framePtr += 8 + (*iter)->mLen;

      (*iter)->mPacketNum = mNextPacketID;
      (*iter)->mTransmitTime = Timestamp();
      (*iter)->mRetransmitted = false;

      // move it to the unacked list
      std::unique_ptr<MozQuicStreamChunk> x(std::move(*iter));
      mUnAcked.push_back(std::move(x));
      iter = mUnWritten.erase(iter);
    } else {
      iter++;
    }
  }

  if (framePtr != (pkt + 17)) {
    // then padding as needed up to 1272
    uint32_t paddingNeeded = kMozQuicMTU - 8 - (framePtr - pkt);
    memset (framePtr, 0, paddingNeeded);
    framePtr += paddingNeeded;

    // then 8 bytes of checksum on cleartext packets
    assert (FNV64size == 8);
    if (FNV64block(pkt, kMozQuicMTU - 8, framePtr) != 0) {
      RaiseError(MOZQUIC_ERR_GENERAL, (char *)"hash err");
      return MOZQUIC_ERR_GENERAL;
    }
    uint32_t code = Transmit(pkt, kMozQuicMTU);
    if (code != MOZQUIC_OK) {
      return code;
    }
    mNextPacketID++;
    // each member of the list needs to 
  }

  if (iter != mUnWritten.end()) {
    return FlushStream0();
  }
  return MOZQUIC_OK;
}

uint64_t
MozQuic::Timestamp()
{
  // ms since epoch
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

uint32_t
MozQuic::Flush()
{
  // obviously have to deal with more than this :)
  assert (mConnectionState == CLIENT_STATE_1RTT);

  if (mConnectionState == CLIENT_STATE_1RTT) {
    return FlushStream0();
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuic::DoWriter(std::unique_ptr<MozQuicStreamChunk> &p)
{

  // TODO NOW - this is not a packet! This is data written
  // from a stream
  // if transmit of this data succeeds, we need to move the pointer to
  // the unacked list

  // obviously have to deal with more than this :)
  assert (mConnectionState ==  CLIENT_STATE_1RTT);

  mUnWritten.push_back(std::move(p));

  return MOZQUIC_OK;
}

}}
