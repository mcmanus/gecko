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

  QuicSession(PRDescIdentity quicIdentity, PRIOMethods *quicMethods,
              mozquic_connection_t *session, mozquic_config_t *config);

  static PRStatus NSPRConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to);
  static PRStatus NSPRClose(PRFileDesc *fd);
  static void SetMethods(PRIOMethods *outMethods);

  PRFileDesc *GetFD() { return mFD; }
private:
  ~QuicSession();

  nsCOMPtr<nsIInterfaceRequestor> mCallbacks;
  nsTArray<nsCString> mALPNList;

  bool         mClosed;
  bool         mDestroyOnClose;
  PRFileDesc  *mFD;
  mozquic_connection_t *mSession;
};

} } // namespace mozilla::net

#endif /* QuicSocketProvider_h__ */

