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
#include <string.h>
#include <fcntl.h>

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

    mozilla::net::MozQuic *q = new mozilla::net::MozQuic(inConfig->handleIO);
    if (!q) {
      return MOZQUIC_ERR_GENERAL;
    }
    *outConnection = (void *)q;

    q->SetClosure(inConfig->closure);
    q->SetLogger(inConfig->logging_callback);
    q->SetTransmiter(inConfig->send_callback);
    q->SetReceiver(inConfig->recv_callback);
    q->SetHandShakeInput(inConfig->handshake_input);
    q->SetErrorCB(inConfig->error_callback);
    q->SetOriginPort(inConfig->originPort);
    
//    connPtr->originName = strdup(inConfig->originName);
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

  int mozquic_start_server(mozquic_connection_t *conn,
                           int (*handle_new_connection)(void *, mozquic_connection_t *newconn))
  {
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn));
    return self->StartServer(handle_new_connection);
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

  void mozquic_handshake_output(mozquic_connection_t *conn,
                                unsigned char *data, uint32_t data_len)
  {
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn));
    self->HandShakeOutput(data, data_len);
  }
  
  
#ifdef __cplusplus
}
#endif

namespace mozilla { namespace net {

MozQuic::MozQuic(bool handleIO)
  : mFD(-1)
  , mHandleIO(handleIO)
  , mIsClient(true)
  , mConnectionState(STATE_UNINITIALIZED)
  , mOriginPort(-1)
  , mVersion(kMozQuicVersion1)
  , mConnectionID(0)
  , mNextPacketID(0)
  , mClosure(this)
  , mLogCallback(nullptr)
  , mTransmitCallback(nullptr)
  , mReceiverCallback(nullptr)
  , mHandShakeInput(nullptr)
  , mErrorCB(nullptr)
  , mNewConnCB(nullptr)
{
  assert(!handleIO); // todo
  // todo seed prng sensibly
  srandom(time(NULL));
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
  mIsClient = true;
  mStream0.reset(new MozQuicStreamPair(0, this));

  mConnectionState = CLIENT_STATE_1RTT;
  for (int i=0; i < 4; i++) {
    mConnectionID = mConnectionID << 16;
    mConnectionID = mConnectionID | (random() & 0xffff);
  }
  for (int i=0; i < 2; i++) {
    mNextPacketID = mNextPacketID << 16;
    mNextPacketID = mNextPacketID | (random() & 0xffff);
  }

  return MOZQUIC_OK;
}

int
MozQuic::StartServer(int (*handle_new_connection)(void *, mozquic_connection_t *))
{
  assert(!mHandleIO); // todo
  mNewConnCB = handle_new_connection;
  mIsClient = false;

  mConnectionState = SERVER_STATE_LISTEN;
  Bind();
  return MOZQUIC_OK;
}

int
MozQuic::Bind()
{
  if (mFD > 0) {
    return MOZQUIC_OK;
  }
  mFD = socket(AF_INET, SOCK_DGRAM, 0); // todo v6 and non 0 addr
  fcntl(mFD, F_SETFL, fcntl(mFD, F_GETFL, 0) | O_NONBLOCK);
  struct sockaddr_in sin;
  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(mOriginPort);
  bind(mFD, (const sockaddr *)&sin, sizeof (sin)); // todo err
  listen(mFD, 1000); // todo err
  return MOZQUIC_OK;
}

uint32_t
MozQuic::Intake()
{
  // check state
  assert (mConnectionState == SERVER_STATE_LISTEN ||
          mConnectionState == SERVER_STATE_1RTT ||
          mConnectionState == CLIENT_STATE_1RTT); // todo mvp

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
    case 0x02: // client initial packet
      if (!ServerState()) {
        Log((char *)"ignore client hello in client state");
        continue;
      }
      ProcessClientInitial(pkt, pktSize);
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
  uint32_t code;
  Log((char *)"IO()\n");

  Intake();
  if (mIsClient) {
    switch (mConnectionState) {
    case CLIENT_STATE_1RTT:
      code = ClientSend1RTT();
      if (code != MOZQUIC_OK) {
        return code;
      }
      break;
    default:
      assert(false);
      // todo
    }
  } else {
    if (mConnectionState == SERVER_STATE_1RTT) {
      assert(false);
    }
  }
  
  return MOZQUIC_OK;
}

void
MozQuic::Log(char *msg) 
{
  // todo default mLogCallback can be dev/null
  if (mLogCallback) {
    mLogCallback(mClosure, msg);
  } else {
    fprintf(stderr,"MozQuic Logger :%s:\n", msg);
  }
}

uint32_t
MozQuic::Recv(unsigned char *pkt, uint32_t avail, uint32_t &outLen)
{
  if (mReceiverCallback) {
    return mReceiverCallback(mClosure, pkt, avail, &outLen);
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
    return mTransmitCallback(mClosure, pkt, len);
  }
  send(mFD, pkt, len, 0); // todo errs
  return MOZQUIC_OK;
}

void
MozQuic::RaiseError(uint32_t e, char *reason)
{
  Log(reason);
  if (mErrorCB) {
    mErrorCB(mClosure, e, reason);
  }
}

// this is called by the application when the application is handling
// the TLS stream (so that it can do more sophisticated handling
// of certs etc like gecko PSM does). The app is providing the
// client hello
void
MozQuic::HandShakeOutput(unsigned char *buf, uint32_t datalen)
{
  mStream0->Write(buf, datalen);
}

int
MozQuic::ClientSend1RTT() 
{
  if (!mHandShakeInput) {
    // todo handle doing this internally
    assert(false);
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"need handshaker");
    return MOZQUIC_ERR_GENERAL;
  }

  Flush();
  if (!mStream0->Empty()) {
    // Server Reply is available
    unsigned char buf[kMozQuicMSS];
    uint32_t amt = 0;
    bool fin = false;
    
    uint32_t code = mStream0->Read(buf, kMozQuicMSS, amt, fin);
    if (code != MOZQUIC_OK) {
      return code;
    }
    if (amt > 0) {
      // called to let the app know that the server hello is ready
      mHandShakeInput(mClosure, buf, amt);
    }
  }
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
  
  return IntakeStream0(pkt, pktSize);
}

int
MozQuic::IntakeStream0(unsigned char *pkt, uint32_t pktSize) 
{
  // used by both client and server
  unsigned char *framePtr = pkt + 17;
  unsigned char *endPtr = pkt + pktSize;

  endPtr -= 8; // checksum. todo mvp verify

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
      memcpy(((char *)&streamID) + (4 - idLen), framePtr, idLen);
      framePtr += idLen;
      streamID = ntohl(streamID);
      if (streamID != 0) {
        RaiseError(MOZQUIC_ERR_GENERAL, (char *) "stream 0 expected");
        return MOZQUIC_ERR_GENERAL;
      }

      uint64_t offset = 0;
      memcpy(((char *)&offset) + (8 - offsetLen), framePtr, offsetLen);
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
  return MOZQUIC_OK;
}

MozQuic *
MozQuic::Accept()
{
  MozQuic *child = new MozQuic(mHandleIO);
  child->mIsClient = false;
  child->mStream0.reset(new MozQuicStreamPair(0, this));
  for (int i=0; i < 4; i++) {
    child->mConnectionID = child->mConnectionID << 16;
    child->mConnectionID = child->mConnectionID | (random() & 0xffff);
  }
  for (int i=0; i < 2; i++) {
    child->mNextPacketID = child->mNextPacketID << 16;
    child->mNextPacketID = child->mNextPacketID | (random() & 0xffff);
  }

  return child;
}

bool
MozQuic::VersionOK(uint32_t proposed)
{
  if (proposed == kMozQuicVersion1 ||
      proposed == kMozQuicIetfID3) {
    return true;
  }
  return false;
}

int
MozQuic::ProcessClientInitial(unsigned char *pkt, uint32_t pktSize)
{
  assert(pkt[0] & 0x80);
  assert(pkt[0] == 0x82);
  assert(pktSize >= 17);
  
  // received type 2
  if (mConnectionState != SERVER_STATE_1RTT &&
      mConnectionState != SERVER_STATE_LISTEN) { // todo rexmit right?
    return MOZQUIC_OK;
  }
  
  if (mConnectionState == SERVER_STATE_LISTEN) {
    // todo mvp, we need some kind of hash to check for dups here
    MozQuic *child = Accept();
    child->mConnectionState = SERVER_STATE_1RTT;
    child->ProcessClientInitial(pkt, pktSize);
    assert(mNewConnCB); // todo handle err
    mNewConnCB(mClosure, child);
    return MOZQUIC_OK;
  }

  // start by checking the version.

  uint32_t tmp32;
  memcpy(&tmp32, pkt + 13, 4);
  tmp32 = ntohl(tmp32);
  if (!VersionOK(tmp32)) {
    // todo real err handling and version negotiation packet
    // todo mvp
    Log((char *)"server version err");
    return MOZQUIC_OK;
  }

  mVersion = tmp32;
  // todo mvp acknowledge this packet
  
  return IntakeStream0(pkt, pktSize);
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

  // this data gets queued to unwritten and framed and
  // transmitted after prioritization by flush()

  // obviously have to deal with more than this :)
  assert (mConnectionState ==  CLIENT_STATE_1RTT);

  mUnWritten.push_back(std::move(p));

  return MOZQUIC_OK;
}

}}
