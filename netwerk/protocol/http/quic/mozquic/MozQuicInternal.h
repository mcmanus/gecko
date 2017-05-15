/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozquicinternal_h__
#define mozquicinternal_h__

#include <netinet/ip.h>
#include <stdint.h>
#include <unistd.h>

namespace mozilla { namespace net {

// todo handle more than 1
static const uint32_t kMozQuicVersion = 0xf123f0c5;
static const uint32_t kMozQuicMTU = 1280; // todo pmtud
    
enum connectionState
{
  CLIENT_STATE_UNINITIALIZED,
  CLIENT_STATE_SEND_0RTT,
  CLIENT_STATE_SEND_1RTT,
  CLIENT_STATE_WAIT_0RTT,
  CLIENT_STATE_WAIT_1RTT,
  CLIENT_STATE_CONNECTED,
  CLIENT_STATE_CLOSED,  // todo more shutdown states

  SERVER_STATE_UNINITIALIZED = 0,
};

class MozQuic final
{
public:
  MozQuic(bool handleIO)
    : mFD(-1)
    , mHandleIO(handleIO)
    , mIsClient(true)
    , mConnectionState(CLIENT_STATE_UNINITIALIZED)
    , mStream0Offset(0)
    , mLogCallback(nullptr)
    , mTransmitCallback(nullptr)
    , mHandShaker(nullptr)
    , mErrorCB(nullptr)
    {}
  ~MozQuic()
  {
    if (mFD > 0) {
      close(mFD);
    }
  }
  
  int StartConnection();
  int IO();

  void SetLogger(void (*fx)(mozquic_connection_t *, char *)) { mLogCallback = fx; }
  void SetTransmiter(int(*fx)(mozquic_connection_t *,
                              unsigned char *, uint32_t)) { mTransmitCallback = fx; }
  void SetHandShaker(int (*fx)(mozquic_connection_t *, int fd)) { mHandShaker = fx; }
  void SetErrorCB(int (*fx)(mozquic_connection_t *, uint32_t err, char *)) { mErrorCB = fx; }
  void SetFD(int fd) { mFD = fd; }
  int  GetFD() { return mFD; }
private:
  void RaiseError(uint32_t err, char *reason);

  int Transmit(unsigned char *, uint32_t len);
  void GetHandShakerData(unsigned char *, uint16_t &out, uint16_t avail);
  int Send1RTT();
  void Log(char *);

  int  mFD;
  bool mHandleIO;
  bool mIsClient;
  enum connectionState mConnectionState;

  uint64_t mConnectionID;
  uint32_t mNextPacketID;
  uint32_t mStream0Offset;

  void (*mLogCallback)(mozquic_connection_t *, char *); // todo va arg
  int  (*mTransmitCallback)(mozquic_connection_t *, unsigned char *, uint32_t len);
  int  (*mHandShaker)(mozquic_connection_t *, int);
  int  (*mErrorCB)(mozquic_connection_t *, uint32_t, char *);
};
}}

#ifdef __cplusplus
extern "C" {
#endif

struct mozquic_connection_t_old {
  //  struct sockaddr_in  v4addr;
  //  struct sockaddr_in6 v6addr;
  int                 isV6;
  char *originName;
  int originPort;
  int handleIO;
  mozilla::net::MozQuic *q;
};

#ifdef __cplusplus
}
#endif
#endif
