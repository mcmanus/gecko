/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "MozQuicStream.h"
#include "NSSHelper.h"

#include "assert.h"
#include "netinet/ip.h"
#include "stdlib.h"
#include "unistd.h"
#include "time.h"
#include "fnv.h"
#include "sys/time.h"
#include <string.h>
#include <fcntl.h>
#include "prerror.h"

#ifdef __cplusplus
extern "C" {
#endif
  static bool mozQuicInit = false;

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
    q->SetHandshakeInput(inConfig->handshake_input);
    q->SetErrorCB(inConfig->error_callback);
    q->SetOriginPort(inConfig->originPort);
    q->SetOriginName(inConfig->originName);
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
    self->HandshakeOutput(data, data_len);
  }

  void mozquic_handshake_complete(mozquic_connection_t *conn, uint32_t errCode)
  {
    mozilla::net::MozQuic *self(reinterpret_cast<mozilla::net::MozQuic *>(conn));
    self->HandshakeComplete(errCode);
  }

  int mozquic_nss_config(char *dir)
  {
    if (mozQuicInit) {
      return MOZQUIC_ERR_GENERAL;
    }
    mozQuicInit = true;
    if (!dir) {
      return MOZQUIC_ERR_INVALID;
    }

    return mozilla::net::NSSHelper::Init(dir);
  }

#ifdef __cplusplus
}
#endif

namespace mozilla { namespace net {

MozQuic::MozQuic(bool handleIO)
  : mFD(-1)
  , mHandleIO(handleIO)
  , mIsClient(true)
  , mIsChild(false)
  , mReceivedServerClearText(false)
  , mConnectionState(STATE_UNINITIALIZED)
  , mOriginPort(-1)
  , mVersion(kMozQuicVersion1)
  , mConnectionID(0)
  , mNextPacketID(0)
  , mClosure(this)
  , mLogCallback(nullptr)
  , mTransmitCallback(nullptr)
  , mReceiverCallback(nullptr)
  , mHandshakeInput(nullptr)
  , mErrorCB(nullptr)
  , mNewConnCB(nullptr)
{
  assert(!handleIO); // todo
  unsigned char seed[4];
  if (SECSuccess != PK11_GenerateRandom(seed, sizeof(seed))) {
    // major badness!
    srandom(Timestamp() & 0xffffffff);
  } else {
    srandom(seed[0] << 24 | seed[1] << 16 | seed[2] << 8 | seed[3]);
  }
  memset(&mPeer, 0, sizeof(mPeer));
}

MozQuic::~MozQuic()
{
  if (!mIsChild && (mFD > 0)) {
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
  assert (!mHandshakeInput); // todo
  return Bind();
}

void
MozQuic::SetOriginName(const char *name)
{
  mOriginName.reset(new char[strlen(name) + 1]);
  strcpy (mOriginName.get(), name);
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
  bind(mFD, (const sockaddr *)&sin, sizeof (sin)); // todo err check
  listen(mFD, 1000); // todo err
  return MOZQUIC_OK;
}

MozQuic *
MozQuic::FindSession(const unsigned char *pkt, uint32_t pktSize)
{
  assert (!mIsChild);
  assert (!mIsClient);
  assert(pktSize >= 17);
  assert(pkt[0] & 0x80); // todo, this needs to work with short headers

  uint32_t version;
  memcpy(&version, pkt + 13, 4);
  version = ntohl(version);
  if (!VersionOK(version)) {
    Log((char *)"find session failed due to verison");
    return nullptr;
  }

  uint64_t connID;
  memcpy(&connID, pkt + 1, 8);
  connID = ntohll(connID);
  auto i = mConnectionHash.find(connID);
  if (i == mConnectionHash.end()) {
    Log((char *)"find session could not find id in hash");
    return nullptr;
  }
  return (*i).second;
}

uint32_t
MozQuic::Intake()
{
  if (mIsChild) {
    // parent does all fd reading
    return MOZQUIC_OK;
  }
  // check state
  assert (mConnectionState == SERVER_STATE_LISTEN ||
          mConnectionState == SERVER_STATE_1RTT ||
          mConnectionState == CLIENT_STATE_CONNECTED ||
          mConnectionState == CLIENT_STATE_1RTT); // todo mvp
  uint32_t rv = MOZQUIC_OK;

  do {
    uint32_t pktSize = 0;
    struct sockaddr_in client;
    rv = Recv(&mPkt[mPktUsed], kMozQuicMSS - mPktUsed, pktSize, &client);
    if (rv == MOZQUIC_OK) {
      mPktUsed += pktSize;
    }
    // todo 17 assumes long form
    if (mPktUsed < 17) {
      // wait for more data
      return MOZQUIC_OK;
    }
    Log((char *)"intake found data");

    if (!(mPkt[0] & 0x80)) {
      // short form header when we only expect long form
      // cleartext
      Log((char *)"short form header at wrong time");
      continue;
    }

    // dispatch to the right MozQuic class. this is used
    // for emphasis
    uint8_t type = mPkt[0] & 0x7f;
    switch (type) {
    case TYPE_VERSION_NEGOTIATION: // version negotiation
      assert(false);
      // todo mvp
      break;
    case TYPE_CLIENT_INITIAL:
      rv = this->ProcessClientInitial(mPkt, pktSize, &client);
      break;
    case TYPE_SERVER_STATELESS_RETRY:
      assert(false);
      // todo mvp
      break;
    case TYPE_SERVER_CLEARTEXT:
      rv = this->ProcessServerCleartext(mPkt, pktSize);
      break;
    case TYPE_CLIENT_CLEARTEXT:
    {
      MozQuic *childSession = FindSession(mPkt, pktSize);
      if (!childSession) {
        rv = MOZQUIC_ERR_GENERAL;
      } else {
        rv = childSession->ProcessClientCleartext(mPkt, pktSize);
      }
    }
    break;

    default:
      // reject anything that is not a cleartext packet (not right, but later)
      Log((char *)"recv1rtt unexpected type");
      // todo this could actually be out of order protected packet even in handshake
      // and ideally would be queued. for now we rely on retrans
      break;
    }

    // TODO: make sure this consumes the correct amount of data here!
    Consumed(pktSize);
  } while (rv == MOZQUIC_OK);

  return rv;
}

int
MozQuic::IO()
{
  uint32_t code;
  Log((char *)"IO()\n");

  Intake();
  Flush();

  if (mIsClient) {
    switch (mConnectionState) {
    case CLIENT_STATE_1RTT:
      code = Client1RTT();
      if (code != MOZQUIC_OK) {
        return code;
      }
      break;
    case CLIENT_STATE_CONNECTED:
      // todo mvp
      break;
    default:
      assert(false);
      // todo
    }
  } else {
    if (mConnectionState == SERVER_STATE_1RTT) {
      code = Server1RTT();
      if (code != MOZQUIC_OK) {
        return code;
      }
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
MozQuic::Recv(unsigned char *pkt, uint32_t avail, uint32_t &outLen,
              struct sockaddr_in *peer)
{
  if (mReceiverCallback) {
    return mReceiverCallback(mClosure, pkt, avail, &outLen);
  }
  socklen_t sinlen = sizeof(*peer);
  ssize_t amt =
    recvfrom(mFD, pkt, avail, 0, (struct sockaddr *) peer, &sinlen);

  outLen = amt > 0 ? amt : 0;
  // todo errs

  return MOZQUIC_OK;
}

 // we have consumed this amount of bytes from the receive buffer
void
MozQuic::Consumed(int bytes)
{
  assert(bytes <= mPktUsed);
  if (mPktUsed > bytes) {
    // move the trailer to the beginning
    memmove(&mPkt[0], &mPkt[mPktUsed], mPktUsed - bytes);
  }
  mPktUsed -= bytes;
}

uint32_t
MozQuic::Transmit (unsigned char *pkt, uint32_t len)
{
  if (mTransmitCallback) {
    return mTransmitCallback(mClosure, pkt, len);
  }
  if (mIsChild) {
    sendto(mFD, pkt, len, 0,
           (sockaddr *)&mPeer, sizeof(mPeer));
  } else {
    send(mFD, pkt, len, 0); // todo errs
  }

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
MozQuic::HandshakeOutput(unsigned char *buf, uint32_t datalen)
{
  mStream0->Write(buf, datalen);
}

// this is called by the application when the application is handling
// the TLS stream (so that it can do more sophisticated handling
// of certs etc like gecko PSM does). The app is providing the
// client hello
void
MozQuic::HandshakeComplete(uint32_t code)
{
  if (!mHandshakeInput) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"not using handshaker api");
    return;
  }
  if (mConnectionState != CLIENT_STATE_1RTT) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"Handshake complete in wrong state");
    return;
  }
  mConnectionState = CLIENT_STATE_CONNECTED;
}

int
MozQuic::Client1RTT()
{
  if (!mHandshakeInput) {
    // todo handle doing this internally
    assert(false);
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"need handshaker");
    return MOZQUIC_ERR_GENERAL;
  }

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
      mHandshakeInput(mClosure, buf, amt);
    }
  }
  return MOZQUIC_OK;
}

int
MozQuic::Server1RTT()
{
  if (mHandshakeInput) {
    // todo handle app-security on server side
    assert(false);
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"need handshaker");
    return MOZQUIC_ERR_GENERAL;
  }

  if (!mStream0->Empty()) {
    uint32_t code = mNSSHelper->DriveHandshake();
    if (code != MOZQUIC_OK) {
      RaiseError(code, (char *) "server 1rtt handshake failed");
      return code;
    }
    if (mNSSHelper->IsHandshakeComplete()) {
      mConnectionState = SERVER_STATE_CONNECTED;
    }
  }
  return MOZQUIC_OK;
}

int
MozQuic::ProcessServerCleartext(unsigned char *pkt, uint32_t pktSize)
{
  // cleartext is always in long form
  assert(pkt[0] & 0x80);
  assert((pkt[0] & 0x7f) == TYPE_SERVER_CLEARTEXT);
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

  mReceivedServerClearText = true;
  memcpy(&mConnectionID, pkt + 1, 8);
  mConnectionID = ntohll(mConnectionID);
  // todo log change

  return IntakeStream0(pkt, pktSize);
}

int
MozQuic::IntakeStream0(unsigned char *pkt, uint32_t pktSize)
{
  // todo this assumes long header
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
      // todo mvp generate ACK (not here tho. we ack packets not data frames)
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
MozQuic::Accept(struct sockaddr_in *clientAddr)
{
  MozQuic *child = new MozQuic(mHandleIO);
  child->mIsChild = true;
  child->mIsClient = false;
  memcpy(&child->mPeer, clientAddr, sizeof (struct sockaddr_in));
  child->mFD = mFD;

  child->mStream0.reset(new MozQuicStreamPair(0, child));
  do {
    for (int i=0; i < 4; i++) {
      child->mConnectionID = child->mConnectionID << 16;
      child->mConnectionID = child->mConnectionID | (random() & 0xffff);
    }
  } while (mConnectionHash.count(child->mConnectionID) != 0);

  for (int i=0; i < 2; i++) {
    child->mNextPacketID = child->mNextPacketID << 16;
    child->mNextPacketID = child->mNextPacketID | (random() & 0xffff);
  }

  assert(!mHandshakeInput);
  if (!mHandshakeInput) {
    child->mNSSHelper.reset(new NSSHelper(child, mOriginName.get()));
  }
  child->mVersion = mVersion;

  mConnectionHash.insert( { child->mConnectionID, child });
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
MozQuic::ProcessClientInitial(unsigned char *pkt, uint32_t pktSize,
                              struct sockaddr_in *clientAddr)
{
  assert(pkt[0] & 0x80);
  assert((pkt[0] & 0x7f) == TYPE_CLIENT_INITIAL);
  assert(pktSize >= 17);
  assert(!mIsChild);

  if (mConnectionState != SERVER_STATE_LISTEN) { // todo rexmit right?
    return MOZQUIC_OK;
  }
  if (mIsClient) {
    return MOZQUIC_ERR_GENERAL;
  }

  // note its possible only the first client initial packet will be subject
  // to the at least 1280 rule, in which case this will need to be updated
  if (pktSize < kMozQuicMTU) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"client initial packet too small");
    return MOZQUIC_ERR_GENERAL;
  }

  // todo - we can get more than one of these if the client hello is very large
  // the >0 packet should not do accept, it should find the session

  // todo mvp acknowledge this packet

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

  MozQuic *child = Accept(clientAddr);
  child->mConnectionState = SERVER_STATE_1RTT;
  child->IntakeStream0(pkt, pktSize);
  assert(mNewConnCB); // todo handle err
  mNewConnCB(mClosure, child);
  return MOZQUIC_OK;
}

int
MozQuic::ProcessClientCleartext(unsigned char *pkt, uint32_t pktSize)
{
  assert(pkt[0] & 0x80);
  assert((pkt[0] & 0x7f) == TYPE_CLIENT_CLEARTEXT);
  assert(pktSize >= 17);
  assert(mIsChild);

  if (mConnectionState != SERVER_STATE_1RTT) { // todo rexmit right?
    return MOZQUIC_ERR_GENERAL;
  }
  assert(!mIsClient);
  assert(mStream0);

  uint32_t tmp32;
  memcpy(&tmp32, pkt + 13, 4);
  tmp32 = ntohl(tmp32);
  if (tmp32 != mVersion) {
    RaiseError(MOZQUIC_ERR_GENERAL, (char *)"version mismatch");
    return MOZQUIC_ERR_GENERAL;
  }

  return IntakeStream0(pkt, pktSize);
}

uint32_t
MozQuic::FlushStream0()
{
  if (mUnWritten.empty()) {
    return MOZQUIC_OK;
  }

  unsigned char pkt[kMozQuicMTU];
  unsigned char *endpkt = pkt + kMozQuicMTU;
  uint32_t tmp32;

  // section 5.4.1 of transport
  // long form header 17 bytes
  pkt[0] = 0x80;
  if (ServerState()) {
    pkt[0] |= TYPE_SERVER_CLEARTEXT;
  } else {
    pkt[0] |= mReceivedServerClearText ? TYPE_CLIENT_CLEARTEXT : TYPE_CLIENT_INITIAL;
  }

  // todo store a big endian version of this
  uint64_t connID = htonll(mConnectionID);
  memcpy(pkt + 1, &connID, 8);

  tmp32 = htonl(mNextPacketID);
  memcpy(pkt + 9, &tmp32, 4);
  tmp32 = htonl(mVersion);
  memcpy(pkt + 13, &tmp32, 4);

  unsigned char *framePtr = pkt + 17;

  auto iter = mUnWritten.begin();
  while (iter != mUnWritten.end()) {
    if ((*iter)->mStreamID == 0) {
      uint32_t room = endpkt - framePtr - 8; // the last 8 are for checksum
      if (room < 9) {
        break; // 8 header bytes and 1 data byte
      }

      // stream header is 8 bytes long
      // 1 type + 2 bytes of len, 1 stream id,
      // 4 bytes of offset. That's type 0xd8
      framePtr[0] = 0xd8;
      uint16_t tmp16 = (*iter)->mLen;
      // todo check range.. that's really wrong as its 32
      tmp16 = htons(tmp16);
      memcpy(framePtr + 1, &tmp16, 2);
      framePtr[3] = 0; // stream 0

      // 4 bytes of offset is normally a waste, but it just comes
      // out of padding
      tmp32 = (*iter)->mOffset;
      tmp32 = htonl(tmp32);
      memcpy(framePtr + 4, &tmp32, 4);
      framePtr += 8;

      room -= 8;
      if (room < (*iter)->mLen) {
        // we need to split this chunk. its too big
        // todo iterate on them all instead of doing this n^2
        // as there is a copy involved
        std::unique_ptr<MozQuicStreamChunk>
          tmp(new MozQuicStreamChunk((*iter)->mStreamID,
                                     (*iter)->mOffset + room,
                                     (*iter)->mData.get() + room,
                                     (*iter)->mLen - room,
                                     (*iter)->mFin));
        (*iter)->mLen = room;
        (*iter)->mFin = false;
        tmp16 = (*iter)->mLen;
        tmp16 = htons(tmp16);
        memcpy(framePtr - 7, &tmp16, 2);
        auto iterReg = iter++;
        mUnWritten.insert(iter, std::move(tmp));
        iter = iterReg;
      }
      assert(room >= (*iter)->mLen);

      memcpy(framePtr, (*iter)->mData.get(), (*iter)->mLen);
      fprintf(stderr,"quic stream output of len %d\n", (*iter)->mLen);
      framePtr += (*iter)->mLen;

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
    // then padding as needed up to 1272 on client_initial
    uint32_t finalLen =
      ((pkt[0] & 0x7f) == TYPE_CLIENT_INITIAL) ? kMozQuicMTU : ((framePtr - pkt) + 8);

    uint32_t paddingNeeded = finalLen - 8 - (framePtr - pkt);
    memset (framePtr, 0, paddingNeeded);
    framePtr += paddingNeeded;

    // then 8 bytes of checksum on cleartext packets
    assert (FNV64size == 8);
    if (FNV64block(pkt, finalLen - 8, framePtr) != 0) {
      RaiseError(MOZQUIC_ERR_GENERAL, (char *)"hash err");
      return MOZQUIC_ERR_GENERAL;
    }
    uint32_t code = Transmit(pkt, finalLen);
    if (code != MOZQUIC_OK) {
      return code;
    }
    mNextPacketID++;
    // each member of the list needs to
  }

  if (iter != mUnWritten.end()) {
    return FlushStream0(); // todo mvp this is broken with non stream 0 pkts
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
  // todo mvp obviously have to deal with more than this :)
  return FlushStream0();
}

uint32_t
MozQuic::DoWriter(std::unique_ptr<MozQuicStreamChunk> &p)
{

  // this data gets queued to unwritten and framed and
  // transmitted after prioritization by flush()

  // obviously have to deal with more than this :)
  assert (mConnectionState == CLIENT_STATE_1RTT ||
          mConnectionState == SERVER_STATE_1RTT);

  mUnWritten.push_back(std::move(p));

  return MOZQUIC_OK;
}

int32_t
MozQuic::NSSInput(void *buf, int32_t amount)
{
  if (mStream0->Empty()) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  // client part of handshake is available in stream 0,
  // feed it to nss via the return code of this fx
  uint32_t amt = 0;
  bool fin = false;

  uint32_t code = mStream0->Read((unsigned char *)buf,
                                 amount, amt, fin);
  if (code != MOZQUIC_OK) {
    PR_SetError(PR_IO_ERROR, 0);
    return -1;
  }
  if (amt > 0) {
    return amt;
  }
  if (fin) {
    return 0;
  }
  PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
  return -1;
}

int32_t
MozQuic::NSSOutput(const void *buf, int32_t amount)
{
  // nss has produced some server output e.g. server hello
  // we need to put it into stream 0 so that it can be
  // written on the network
  return mStream0->Write((const unsigned char *)buf, amount);
}

}}
