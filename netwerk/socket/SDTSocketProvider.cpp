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
#include "SDTSocketProvider.h"
#include "nsISocketProviderService.h"
#include "nsNetCID.h"
#include "SDTUpper.h"

#if 0
 /* README

 TODO Patrick's list (at best a partial list)
 * reliabiity (optional).. via ack.. notion of deadline notion of ack with uni-tt
 * happy eyeballs
 * uuid and h2 should be able to go longer the normal connect/close cycle..
 * timeouts
 * mtu detection
 * congestion control (latency sensitive)
 * poll()
 * fec
 * psm integration for auth and cipher selection
 * investigate dtlscon pmtu change
 * have psm and http use common pref for finding transport layer
 * better h2 integration where fec is per headers and reliability per stream
 * lib logging
 * assert normalization
 */
#endif

// dtls 1.2 rfc 6437, tls 1.2 rfc 5246

using mozilla::LogLevel;

namespace mozilla { namespace net {

LazyLogModule gSDTLog("sdt");
#define LOG(args) MOZ_LOG(gSDTLog, mozilla::LogLevel::Debug, args)

SDTSocketProvider::SDTSocketProvider()
{
}

SDTSocketProvider::~SDTSocketProvider()
{
}

NS_IMETHODIMP
SDTSocketProvider::NewSocket(int32_t family,
                             const char *host,
                             int32_t port,
                             nsIProxyInfo *proxy,
                             const OriginAttributes &aOriginAttributes,
                             uint32_t flags,
                             PRFileDesc **result,
                             nsISupports **securityInfo)
{
  PRFileDesc *fd = nullptr;
  PRFileDesc *sdtFd = nullptr;
  nsCOMPtr<nsISocketProvider> provider;
  nsCOMPtr<nsISupports> secInfo;
  nsCOMPtr<nsISocketProviderService> spserv;

  nsresult rv;

  LOG(("SDTSocketProvider::NewSocket %p\n", this));

  fd = sdt_openSocket(family);

  if (fd <= 0) {
    LOG(("SDTSocketProvider::NewSocket fail %p\n", this));
    goto onfail;
  }

  spserv = do_GetService(NS_SOCKETPROVIDERSERVICE_CID, &rv);
  if (NS_FAILED(rv)) {
    goto onfail;
  }

  rv = spserv->GetSocketProvider("ssl", getter_AddRefs(provider));
  if (NS_FAILED(rv)) {
    goto onfail;
  }

  rv = provider->AddToSocket(family, host, port, proxy, aOriginAttributes,
                             flags, fd, getter_AddRefs(secInfo));

  if (NS_FAILED(rv)) {
    goto onfail;
  }

  fd = sdt_addALayer(fd);
  if (fd <= 0) {
    goto onfail;
  }

  sdtFd = sdt_createSDTSocket(fd);
  if (sdtFd <= 0) {
    goto onfail;
  }

  *result = sdtFd;
  secInfo.forget(securityInfo);

  LOG(("SDTSocketProvider::NewSocket ok %p\n", this));
  return NS_OK;

onfail:
  LOG(("SDTSocketProvider::NewSocket fail %p\n", this));
  MOZ_ASSERT(false, "to be removed");

  if (fd) {
    PR_Close(fd);
  }
  if (sdtFd) {
    PR_Close(sdtFd);
  }
  return NS_ERROR_SOCKET_CREATE_FAILED;
}

NS_IMETHODIMP
SDTSocketProvider::AddToSocket(int32_t family,
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


NS_IMPL_ISUPPORTS(SDTSocketProvider, nsISocketProvider)

} } // namespace mozilla::net

