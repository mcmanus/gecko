/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Logging.h"
#include "nsCOMPtr.h"
#include "nsIServiceManager.h"
#include "nsIUUIDGenerator.h"
#include "nspr.h"
#include "sdt.h"
#include "QuicSocketProvider.h"
#include "nsISocketProviderService.h"
#include "nsNetCID.h"
#include "SDTUpper.h"
#include "QuicLog.h"
#include "QuicSession.h"
#include "MozQuic.h"

// a quic socket mostly holds some configuration data
using mozilla::LogLevel;

namespace mozilla { namespace net {

LazyLogModule gQUICLog("quic");

QuicSocketProvider::QuicSocketProvider()
{
}

QuicSocketProvider::~QuicSocketProvider()
{
}

NS_IMETHODIMP
QuicSocketProvider::NewSocket(int32_t family,
                             const char *host,
                             int32_t port,
                             nsIProxyInfo *proxy,
                             const OriginAttributes &aOriginAttributes,
                             uint32_t flags,
                             PRFileDesc **result,
                             nsISupports **securityInfo)
{
  // todo securityinfo - nsISSLSocketControl
  LOG(("QuicSocketProvider::NewSocket %p\n", this));

  QuicSession *qSession = new QuicSession(host, port, family == AF_INET);
  
  LOG(("QuicSocketProvider::NewSocket ok %p\n", this));
  *result = qSession->GetFD();
  nsCOMPtr<nsISupports> secInfo(qSession);
  *securityInfo = secInfo.forget().take();
  return NS_OK;
}

NS_IMETHODIMP
QuicSocketProvider::AddToSocket(int32_t family,
                               const char *host,
                               int32_t port,
                               nsIProxyInfo *proxy,
                               const OriginAttributes &aOriginAttributes,
                               uint32_t flags,
                               PRFileDesc *sock,
                               nsISupports **socksInfo)
{
  return NS_ERROR_SOCKET_CREATE_FAILED;
}


NS_IMPL_ISUPPORTS(QuicSocketProvider, nsISocketProvider)
#undef LOG

} } // namespace mozilla::net

