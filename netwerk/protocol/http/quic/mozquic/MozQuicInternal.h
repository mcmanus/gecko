/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <netinet/ip.h>
#include <stdint.h>
#include <unistd.h>
#include <forward_list>
#include <unordered_map>
#include <memory>
#include "MozQuicStream.h"
#include "NSSHelper.h"

namespace mozilla { namespace net {

// todo handle more than 1
static const uint32_t kMozQuicVersion1 = 0xf123f0c5;
static const uint32_t kMozQuicIetfID3 = 0xff000003;

static const uint32_t kMozQuicMTU = 1280; // todo pmtud
static const uint32_t kMozQuicMSS = 16384;

static inline uint64_t htonll(uint64_t x)
{
  uint32_t test = 0x12345678;
  if (test == htonl(test)) {
    return x; // host and network order are the same
  }
  return ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32));
}

static inline uint64_t ntohll(uint64_t x)
{
  return htonll(x);
}

enum connectionState
{
  STATE_UNINITIALIZED,
  CLIENT_STATE_0RTT,
  CLIENT_STATE_1RTT,
  CLIENT_STATE_CONNECTED,
  CLIENT_STATE_CLOSED,  // todo more shutdown states

  CLIENT_STATE_BREAK,
  SERVER_STATE_BREAK,
  
  SERVER_STATE_LISTEN,
  SERVER_STATE_0RTT,
  SERVER_STATE_1RTT,
  SERVER_STATE_CONNECTED,
  SERVER_STATE_CLOSED,
};

class MozQuicStreamPair;

class MozQuic final : public MozQuicWriter
{
public:
  MozQuic(bool handleIO);
  MozQuic();
  ~MozQuic();

  int StartConnection();
  int StartServer(int (*handle_new_connection)(void *, mozquic_connection_t *));
  int IO();
  void HandshakeOutput(unsigned char *, uint32_t amt);
  void HandshakeComplete(uint32_t errCode);

  void SetOriginPort(int port) { mOriginPort = port; }
  void SetOriginName(const char *name);
  void SetClosure(void *closure) { mClosure = closure; }
  void SetLogger(void (*fx)(mozquic_connection_t *, char *)) { mLogCallback = fx; }
  void SetTransmiter(int(*fx)(mozquic_connection_t *,
                              unsigned char *, uint32_t)) { mTransmitCallback = fx; }
  void SetReceiver(int(*fx)(mozquic_connection_t *,
                            unsigned char *, uint32_t, uint32_t *)) { mReceiverCallback = fx; }
  void SetHandshakeInput(int (*fx)(mozquic_connection_t *,
                                   unsigned char *data, uint32_t len)) { mHandshakeInput = fx; }
  void SetErrorCB(int (*fx)(mozquic_connection_t *, uint32_t err, char *)) { mErrorCB = fx; }
  void SetFD(int fd) { mFD = fd; }
  int  GetFD() { return mFD; }

  uint32_t DoWriter(std::unique_ptr<MozQuicStreamChunk> &p) override;
private:
  void RaiseError(uint32_t err, char *reason);

  uint32_t Transmit(unsigned char *, uint32_t len);
  uint32_t Recv(unsigned char *, uint32_t len, uint32_t &outLen, struct sockaddr_in *peer);
  void Consumed(int bytes);
  int ProcessServerCleartext(unsigned char *, uint32_t size);
  int ProcessClientInitial(unsigned char *, uint32_t size, struct sockaddr_in *peer);
  int ProcessClientCleartext(unsigned char *pkt, uint32_t pktSize);
  int IntakeStream0(unsigned char *, uint32_t size);

  bool ServerState() { return mConnectionState > SERVER_STATE_BREAK; }
  MozQuic *FindSession(const unsigned char *pkt, uint32_t pktSize);
  
  uint64_t Timestamp();
  uint32_t Intake();
  uint32_t Flush();
  uint32_t FlushStream0();
  int Client1RTT();
  int Server1RTT();
  void Log(char *);
  int Bind();
  bool VersionOK(uint32_t proposed);
  MozQuic *Accept(struct sockaddr_in *peer);

  unsigned char mPkt[kMozQuicMSS]; // receive buffer
  int mPktUsed;                    // bytes in in use

  int  mFD;
  bool mHandleIO;
  bool mIsClient;
  bool mIsChild;
  bool mReceivedServerClearText;
  enum connectionState mConnectionState;
  int mOriginPort;
  std::unique_ptr<char []> mOriginName;
  struct sockaddr_in mPeer; // todo not a v4 world

  uint32_t mVersion;

  // todo mvp lifecycle.. stuff never comes out of here
  std::unordered_map<uint64_t, MozQuic *> mConnectionHash;

  uint64_t mConnectionID;
  uint32_t mNextPacketID;

  void *mClosure;
  void (*mLogCallback)(mozquic_connection_t *, char *); // todo va arg
  int  (*mTransmitCallback)(mozquic_connection_t *, unsigned char *, uint32_t len);
  int  (*mReceiverCallback)(mozquic_connection_t *, unsigned char *, uint32_t len, uint32_t *outlen);
  int  (*mHandshakeInput)(mozquic_connection_t *, unsigned char *, uint32_t len);
  int  (*mErrorCB)(mozquic_connection_t *, uint32_t, char *);
  int  (*mNewConnCB)(void *, mozquic_connection_t *);
  
  std::unique_ptr<MozQuicStreamPair> mStream0;
  std::unique_ptr<NSSHelper>         mNSSHelper;

  // todo this is suboptimal
  std::list<std::unique_ptr<MozQuicStreamChunk>> mUnWritten;
  std::list<std::unique_ptr<MozQuicStreamChunk>> mUnAcked;

public: // callbacks from nsshelper
  int32_t NSSInput(void *buf, int32_t amount);
  int32_t NSSOutput(const void *buf, int32_t amount);

public:
  enum FrameType {
    FRAME_TYPE_PADDING           = 0x0,
    FRAME_TYPE_RST_STREAM        = 0x1,
    FRAME_TYPE_CLOSE             = 0x2,
    FRAME_TYPE_GOAWAY            = 0x3,
    FRAME_TYPE_MAX_DATA          = 0x4,
    FRAME_TYPE_MAX_STREAM_DATA   = 0x5,
    FRAME_TYPE_MAX_STREAM_ID     = 0x6,
    FRAME_TYPE_PING              = 0x7,
    FRAME_TYPE_BLOCKED           = 0x8,
    FRAME_TYPE_STREAM_BLOCKED    = 0x9,
    FRAME_TYPE_STREAM_ID_NEEDED  = 0xA,
    FRAME_TYPE_NEW_CONNECTION_ID = 0xB,
    // ACK                       = 0xa0 - 0xbf
    FRAME_MASK_ACK               = 0xe0,
    FRAME_MASK_ACK_RESULT        = 0xa0,
    // STREAM                    = 0xc0 - 0xff
    FRAME_MASK_STREAM            = 0xc0,
    FRAME_MASK_STREAM_RESULT     = 0xc0,
  };

  enum LongHeaderType {
    TYPE_VERSION_NEGOTIATION    = 1,
    TYPE_CLIENT_INITIAL         = 2,
    TYPE_SERVER_STATELESS_RETRY = 3,
    TYPE_SERVER_CLEARTEXT       = 4,
    TYPE_CLIENT_CLEARTEXT       = 5,
    TYPE_0RTT_PROTECTED         = 6,
    TYPE_1RTT_PROTECTED_KP0     = 7,
    TYPE_1RTT_PROTECTED_KP1     = 8,
    TYPE_PUBLIC_RESET           = 9,
  };
};

}} //namespace
