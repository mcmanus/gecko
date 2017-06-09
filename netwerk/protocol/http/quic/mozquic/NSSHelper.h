/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "prio.h"
#include "ssl.h"
#include "pk11pub.h"

namespace mozquic {

class MozQuic;

class NSSHelper final 
{
public:
  static int Init(char *dir);
  NSSHelper(MozQuic *quicSession, const char *originKey);
  ~NSSHelper() {}
  uint32_t DriveHandshake();
  bool IsHandshakeComplete() { return mHandshakeComplete; }
    
private:
  static PRStatus NSPRGetPeerName(PRFileDesc *aFD, PRNetAddr*addr);
  static PRStatus NSPRGetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt);
  static PRStatus nssHelperConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to);
  static int nssHelperWrite(PRFileDesc *aFD, const void *aBuf, int32_t aAmount);
  static int nssHelperSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                           int , PRIntervalTime);
  static int32_t nssHelperRead(PRFileDesc *fd, void *buf, int32_t amount);
  static int32_t nssHelperRecv(PRFileDesc *fd, void *buf, int32_t amount, int flags,
                               PRIntervalTime timeout);

  static void HandshakeCallback(PRFileDesc *fd, void *client_data);

  MozQuic             *mQuicSession;
  PRFileDesc          *mFD;
  bool                 mServerReady;
  bool                 mHandshakeComplete;
};

} //namespace
