/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef QuicSession_h__
#define QuicSession_h__

#pragma once

#include "nspr.h"
#include "MozQuic.h"
#include "nsISSLSocketControl.h"
#include "nsIPipe.h"
#include "nsCOMPtr.h"
#include "nsString.h"
#include "nsTArray.h"

class nsIInterfaceRequestor;

namespace mozilla { namespace net {

class QuicSession final :
  public nsISSLSocketControl      
{
public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSISSLSOCKETCONTROL

  QuicSession(const char *host, int32_t port, bool v4);

  PRFileDesc *GetFD() { return mFD; }
private:
  ~QuicSession();

  static PRStatus NSPRGetPeerName(PRFileDesc *aFD, PRNetAddr*addr);
  static PRStatus NSPRGetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt);
  static PRStatus NSPRConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to);
  static PRStatus NSPRClose(PRFileDesc *fd);
  static void SetMethods(PRIOMethods *quitMethods, PRIOMethods *psmHelperMethods);
  static int MozQuicHandshakeCallback(mozquic_connection_t *session,
                                      unsigned char *data, uint32_t len);
  static int psmHelperWrite(PRFileDesc *aFD, const void *aBuf, int32_t aAmount);
  static int psmHelperSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                           int , PRIntervalTime);
  static PRStatus psmHelperConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to);
  static int32_t psmHelperRead(PRFileDesc *fd, void *buf, int32_t amount);
  static int32_t psmHelperRecv(PRFileDesc *fd, void *buf, int32_t amount, int flags,
                               PRIntervalTime timeout);
  
  nsCOMPtr<nsIInterfaceRequestor> mCallbacks;
  nsTArray<nsCString> mALPNList;

  bool         mClosed;
  bool         mDestroyOnClose;
  PRFileDesc  *mFD;
  mozquic_connection_t *mSession;

  PRFileDesc           *mPSMHelper;
  nsCOMPtr<nsISupports> mPSMHelperSecInfo;
  nsCOMPtr<nsISSLSocketControl> mPSMSSLSocketControl;
  nsCOMPtr<nsIAsyncInputStream> mPSMBufferInput;
  nsCOMPtr<nsIAsyncOutputStream> mPSMBufferOutput;
};

} } // namespace mozilla::net

#endif /* QuicSocketProvider_h__ */

