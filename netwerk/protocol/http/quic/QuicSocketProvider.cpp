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
static bool quicInit = false;
static PRDescIdentity quicIdentity;
static PRIOMethods quicMethods;

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
  LOG(("QuicSocketProvider::NewSocket %p\n", this));

  if (!quicInit) {
    quicInit = true;
    quicIdentity = PR_GetUniqueIdentity("quicSocket");
    quicMethods = *PR_GetDefaultIOMethods();
    QuicSession::SetMethods(&quicMethods);
  }

  PRFileDesc *fd = nullptr;
  struct mozquic_connection_t *session = nullptr;
  struct mozquic_config_t config;

  fd = PR_CreateIOLayerStub(quicIdentity, &quicMethods);
  if (!fd) {
    goto onfail;
  }

  memset (&config, 0, sizeof (config));
  config.domain = family;
  config.originName = host;
  config.originPort = port;

  if (mozquic_new_connection(&session, &config) != MOZQUIC_OK) {
    goto onfail;
  }
  new QuicSession(fd, session); // fd takes possession of session ptr

  LOG(("QuicSocketProvider::NewSocket ok %p\n", this));
  *result = fd;
  return NS_OK;

onfail:
  LOG(("QuicSocketProvider::NewSocket fail %p\n", this));

  if (fd) {
    PR_Close(fd);
    *result = nullptr;

  }
  if (session) {
    mozquic_destroy_connection(session);
  }
  return NS_ERROR_SOCKET_CREATE_FAILED;
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

