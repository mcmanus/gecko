/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "nspr.h"
#include "nsISSLSocketControl.h"
#include "nsISSLStatusProvider.h"
#include "nsIPipe.h"
#include "nsCOMPtr.h"
#include "nsString.h"
#include "nsTArray.h"
#include "mozilla/UniquePtr.h"
#include "ssl.h"
#include "sslexp.h"
#include "nsAHttpConnection.h"

class nsIInterfaceRequestor;
typedef void mozquic_connection_t;
typedef void mozquic_stream_t;

#define NS_QUICSOCKET_IID                                               \
  { 0xdebeeac0, 0x45c3, 0x4379, { 0xb2, 0x3d, 0x93, 0x27, 0x3a, 0xfa, 0x1d, 0xb4 } }

namespace mozilla { namespace net {

class QuicSocket final
  : public nsISSLSocketControl
  , public nsISSLStatusProvider
{
public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSISSLSOCKETCONTROL
  NS_DECL_NSISSLSTATUSPROVIDER
  NS_DECLARE_STATIC_IID_ACCESSOR(NS_QUICSOCKET_IID)

  QuicSocket(const char *host, int32_t port, bool v4);

  static QuicSocket *GetFromFD(PRFileDesc *fd);
          
  PRFileDesc *GetFD() { return mFD; }
  mozquic_stream_t *NewStream();
  void IO();
  void SetConnection(nsAHttpConnection *c) { mConnection = c; }

private:
  ~QuicSocket();

  static PRStatus NSPRGetPeerName(PRFileDesc *aFD, PRNetAddr*addr);
  static PRStatus NSPRGetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt);
  static PRStatus NSPRSetSocketOption(PRFileDesc *fd, const PRSocketOptionData *data);
  static PRStatus NSPRConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to);
  static PRStatus NSPRClose(PRFileDesc *fd);
  static int NSPRWrite(PRFileDesc *aFD, const void *aBuf, int32_t aAmount);
  static int NSPRSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                      int , PRIntervalTime);
  static void SetMethods(PRIOMethods *quitMethods, PRIOMethods *psmHelperMethods);
  int MozQuicHandshakeCallback(unsigned char *data, uint32_t len);
  static int psmHelperWrite(PRFileDesc *aFD, const void *aBuf, int32_t aAmount);
  static int psmHelperSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                           int , PRIntervalTime);
  static PRStatus psmHelperConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to);
  static int32_t psmHelperRead(PRFileDesc *fd, void *buf, int32_t amount);
  static int32_t psmHelperRecv(PRFileDesc *fd, void *buf, int32_t amount, int flags,
                               PRIntervalTime timeout);
  static PRStatus psmHelperClose(PRFileDesc *fd); // deletes self
  static int MozQuicEventCallback(void *closure, uint32_t event, void *param);

  static PRBool TransportExtensionWriter(PRFileDesc *fd, SSLHandshakeType m, PRUint8 *data,
                                         unsigned int *len, unsigned int maxlen, void *arg);
  static SECStatus TransportExtensionHandler(PRFileDesc *fd, SSLHandshakeType m, const PRUint8 *data,
                                             unsigned int len, SSLAlertDescription *alert, void *arg);

  nsCOMPtr<nsIInterfaceRequestor> mCallbacks;
  nsTArray<nsCString> mALPNList;

  bool         mClosed;
  bool         mDestroyOnClose;
  PRFileDesc  *mFD;
  mozquic_connection_t *mSession;
  bool         mQuicConnected;
  RefPtr<nsAHttpConnection> mConnection;

  UniquePtr<unsigned char[]> mTransportParamsToWrite;
  uint32_t                   mTransportParamsToWriteLen;
  PRFileDesc           *mPSMHelper;
  nsCOMPtr<nsISupports> mPSMHelperSecInfo;
  nsCOMPtr<nsISSLSocketControl> mPSMSSLSocketControl;
  nsCOMPtr<nsIAsyncInputStream> mPSMBufferInput;
  nsCOMPtr<nsIAsyncOutputStream> mPSMBufferOutput;
  uint32_t mHandshakeCompleteCode;
};

} } // namespace mozilla::net
