/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Assertions.h"
#include "QuicSession.h"
#include "private/pprio.h"
#include <sys/socket.h>
#include "nsIInterfaceRequestor.h"
#include "nsISocketProviderService.h"
#include "nsISocketProvider.h"
#include "nsNetCID.h"
#include "nsServiceManagerUtils.h"   // do_GetService

namespace mozilla { namespace net {

static bool quicInit = false;
static PRDescIdentity quicIdentity, psmHelperIdentity;
static PRIOMethods quicMethods, psmHelperMethods;

QuicSession::QuicSession(const char *host, int32_t port, bool v4)
  : mClosed(false)
  , mDestroyOnClose(true)
{
  if (!quicInit) {
    quicInit = true;
    quicIdentity = PR_GetUniqueIdentity("quicSocket");
    psmHelperIdentity = PR_GetUniqueIdentity("psmHelper");
    quicMethods = *PR_GetDefaultIOMethods();
    psmHelperMethods = *PR_GetDefaultIOMethods();
    SetMethods(&quicMethods, &psmHelperMethods);
  }

  mozquic_config_t config;
  memset (&config, 0, sizeof (config));
  config.originName = host;
  config.originPort = port;
  config.handleIO = 0;
  config.closure = this;
  config.handshake_input = MozQuicHandshakeCallback;

  // todo deal with failures
  mozquic_new_connection(&mSession, &config);
 
  mFD =
    PR_OpenUDPSocket(v4 ? PR_AF_INET : PR_AF_INET6);
  PRFileDesc *fd = PR_CreateIOLayerStub(quicIdentity, &quicMethods);
  fd->secret = (struct PRFilePrivate *)this;
  PR_PushIOLayer(mFD, PR_NSPR_IO_LAYER, fd);

  mPSMHelper = PR_CreateIOLayerStub(psmHelperIdentity, &psmHelperMethods);
  mPSMHelper->secret = (struct PRFilePrivate *)this;

  nsCOMPtr<nsISupports> secinfo;
  nsCOMPtr<nsISocketProvider> provider;
  nsCOMPtr<nsISocketProviderService> spserv = // todo mozilla::services cache
    do_GetService(NS_SOCKETPROVIDERSERVICE_CONTRACTID);

  if (spserv) {
    spserv->GetSocketProvider("ssl", getter_AddRefs(provider));
  }
  provider->AddToSocket(PR_AF_INET, host, port, nullptr,
                        OriginAttributes(), 0, mPSMHelper,
                        getter_AddRefs(secinfo));  
}

QuicSession::~QuicSession()
{
  if (mSession) {
    mozquic_destroy_connection(mSession);
    mSession = nullptr;
  }

  mDestroyOnClose = false;
  if (mFD) {
    PR_Close(mFD);
    mFD = nullptr;
  }
}

NS_IMETHODIMP
QuicSession::DriveHandshake()
{
  fprintf(stderr,"drivehandshake\n");
  // TODO - feed mozquic via mozquic_handshake_output() tls to send to server
  // in drivehandshake()
  return (mozquic_IO(mSession) == MOZQUIC_OK) ? NS_OK : NS_ERROR_FAILURE;
}

int
QuicSession::MozQuicHandshakeCallback(void *closure,
                                      unsigned char *data, uint32_t len)
{
  QuicSession *self = reinterpret_cast<QuicSession *>(closure);
  // TODO - feed this data to PSM as it is the server reply
  return MOZQUIC_OK;
}

PRStatus
QuicSession::NSPRClose(PRFileDesc *fd)
{
  QuicSession *self = reinterpret_cast<QuicSession *>(fd->secret);
  fd->secret = nullptr;
  PRFileDesc *top = PR_PopIOLayer(fd, PR_TOP_IO_LAYER);
  top->dtor(top);
  self->mFD = nullptr;

  self->mClosed = true;
  if (self->mDestroyOnClose) {
    delete self;
  }
  return (fd->methods->close)(fd);
}

void
QuicSession::SetMethods(PRIOMethods *quicMethods, PRIOMethods *psmHelperMethods)
{
  if (quicMethods) {
    quicMethods->connect = NSPRConnect;
    quicMethods->close =   NSPRClose;
  }
}

PRStatus
QuicSession::NSPRConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  QuicSession *self = reinterpret_cast<QuicSession *>(fd->secret);
  if (!self || self->mClosed || !self->mSession) {
    return PR_FAILURE;
  }
  PRStatus connResult = fd->lower->methods->connect(fd->lower, addr, to);
  if (connResult != PR_SUCCESS) {
    return connResult;
  }

  mozquic_setosfd(self->mSession, PR_FileDesc2NativeHandle(fd));
  if (mozquic_start_connection(self->mSession) != MOZQUIC_OK) {
    return PR_FAILURE;
  }

  return PR_SUCCESS;
}

// nsISSLSocketControl

/* attribute nsIInterfaceRequestor notificationCallbacks; */
NS_IMETHODIMP QuicSession::GetNotificationCallbacks(nsIInterfaceRequestor * *aNotificationCallbacks)
{
  nsCOMPtr<nsIInterfaceRequestor> rv(mCallbacks);
  *aNotificationCallbacks = rv.forget().take();
  return NS_OK;
}
NS_IMETHODIMP QuicSession::SetNotificationCallbacks(nsIInterfaceRequestor *aNotificationCallbacks)
{
  mCallbacks = aNotificationCallbacks;
  return NS_OK;
}

/* void proxyStartSSL (); */
NS_IMETHODIMP QuicSession::ProxyStartSSL()
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* void StartTLS (); */
NS_IMETHODIMP QuicSession::StartTLS()
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP QuicSession::SetNPNList(nsTArray<nsCString> & aList)
{
  // this is baked into quic in a way it is not for generic tls
  return NS_OK;
}

/* readonly attribute ACString negotiatedNPN; */
NS_IMETHODIMP QuicSession::GetNegotiatedNPN(nsACString & aNegotiatedNPN)
{
  // todo
  return NS_ERROR_NOT_CONNECTED;
}

/* ACString getAlpnEarlySelection (); */
NS_IMETHODIMP QuicSession::GetAlpnEarlySelection(nsACString & _retval)
{
  // need to get historic data from nss
  // todo
  return NS_ERROR_NOT_AVAILABLE;
}

/* readonly attribute bool earlyDataAccepted; */
NS_IMETHODIMP QuicSession::GetEarlyDataAccepted(bool *aEarlyDataAccepted)
{
  // todo
  *aEarlyDataAccepted = false;
  return NS_OK;
}

/* boolean joinConnection (in ACString npnProtocol, in ACString hostname, in long port); */
NS_IMETHODIMP QuicSession::JoinConnection(const nsACString & npnProtocol, const nsACString & hostname, int32_t port, bool *_retval)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* boolean testJoinConnection (in ACString npnProtocol, in ACString hostname, in long port); */
NS_IMETHODIMP QuicSession::TestJoinConnection(const nsACString & npnProtocol, const nsACString & hostname, int32_t port, bool *_retval)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* boolean isAcceptableForHost (in ACString hostname); */
NS_IMETHODIMP QuicSession::IsAcceptableForHost(const nsACString & hostname, bool *_retval)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* [infallible] readonly attribute short KEAUsed; */
NS_IMETHODIMP QuicSession::GetKEAUsed(int16_t *aKEAUsed)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* [infallible] readonly attribute unsigned long KEAKeyBits; */
NS_IMETHODIMP QuicSession::GetKEAKeyBits(uint32_t *aKEAKeyBits)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* readonly attribute uint32_t providerFlags; */
NS_IMETHODIMP QuicSession::GetProviderFlags(uint32_t *aProviderFlags)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* [infallible] readonly attribute short SSLVersionUsed; */
NS_IMETHODIMP QuicSession::GetSSLVersionUsed(int16_t *aSSLVersionUsed)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* [infallible] readonly attribute short SSLVersionOffered; */
NS_IMETHODIMP QuicSession::GetSSLVersionOffered(int16_t *aSSLVersionOffered)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* [infallible] readonly attribute short MACAlgorithmUsed; */
NS_IMETHODIMP QuicSession::GetMACAlgorithmUsed(int16_t *aMACAlgorithmUsed)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* attribute nsIX509Cert clientCert; */
NS_IMETHODIMP QuicSession::GetClientCert(nsIX509Cert * *aClientCert)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}
NS_IMETHODIMP QuicSession::SetClientCert(nsIX509Cert *aClientCert)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* [infallible] readonly attribute boolean bypassAuthentication; */
NS_IMETHODIMP QuicSession::GetBypassAuthentication(bool *aBypassAuthentication)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* [infallible] readonly attribute boolean failedVerification; */
NS_IMETHODIMP QuicSession::GetFailedVerification(bool *aFailedVerification)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMPL_ISUPPORTS(QuicSession, nsISSLSocketControl)
  
} } // namespace mozilla::net


