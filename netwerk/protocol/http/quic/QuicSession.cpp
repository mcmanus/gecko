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
#include "nsIAsyncInputStream.h"
#include "nsIAsyncOutputStream.h"
#include "mozilla/Unused.h"
#include "QuicSessionUtil.h"
#include "nsISSLStatusProvider.h"
#include "nsISSLStatus.h"

namespace mozilla { namespace net {

static bool quicInit = false;
static PRDescIdentity quicIdentity, psmHelperIdentity;
static PRIOMethods quicMethods, psmHelperMethods;

QuicSession::QuicSession(const char *host, int32_t port, bool v4)
  : mClosed(false)
  , mDestroyOnClose(true)
  , mHandshakeCompleteCode(MOZQUIC_ERR_GENERAL)
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

  // config.greaseVersionNegotiation = true;

  // todo deal with failures
  mozquic_new_connection(&mSession, &config);
 
  mFD =
    PR_OpenUDPSocket(v4 ? PR_AF_INET : PR_AF_INET6);
  PRFileDesc *fd = PR_CreateIOLayerStub(quicIdentity, &quicMethods);
  fd->secret = (struct PRFilePrivate *)this;
  PR_PushIOLayer(mFD, PR_NSPR_IO_LAYER, fd);

  mPSMHelper = PR_CreateIOLayerStub(psmHelperIdentity, &psmHelperMethods);
  mPSMHelper->secret = (struct PRFilePrivate *)this;

  nsCOMPtr<nsISocketProvider> provider;
  nsCOMPtr<nsISocketProviderService> spserv = // todo mozilla::services cache
    do_GetService(NS_SOCKETPROVIDERSERVICE_CONTRACTID);

  if (spserv) {
    spserv->GetSocketProvider("ssl", getter_AddRefs(provider));
  }

  provider->AddToSocket(PR_AF_INET, host, port, nullptr,
                        OriginAttributes(), 0, mPSMHelper,
                        getter_AddRefs(mPSMHelperSecInfo));
    
  mPSMSSLSocketControl = do_QueryInterface(mPSMHelperSecInfo);
  PRNetAddr addr;
  memset(&addr,0,sizeof(addr));
  addr.raw.family = PR_AF_INET;
  PR_Connect(mPSMHelper, &addr, 0);

  Unused << NS_NewPipe2(getter_AddRefs(mPSMBufferInput),
                        getter_AddRefs(mPSMBufferOutput),
                        true, true, 0, UINT32_MAX);
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
  if (mPSMHelper) {
    PR_Close(mPSMHelper);
    mPSMHelper = nullptr;
  }
}

NS_IMETHODIMP
QuicSession::DriveHandshake()
{
  fprintf(stderr,"drivehandshake\n");
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  nsresult rv = mPSMSSLSocketControl->DriveHandshake();
  if (NS_FAILED(rv) && rv != NS_BASE_STREAM_WOULD_BLOCK) {
    fprintf(stderr,"drivehandshake failed\n");
    mozquic_handshake_complete(mSession, MOZQUIC_ERR_CRYPTO, nullptr);
    mHandshakeCompleteCode = MOZQUIC_ERR_CRYPTO;
  }

  if (NS_SUCCEEDED(rv) && mHandshakeCompleteCode != MOZQUIC_OK) {
    nsCOMPtr<nsISSLStatusProvider> sslprov = do_QueryInterface(mPSMHelperSecInfo);
    nsCOMPtr<nsISSLStatus> sslStatus;
    if (sslprov) {
      sslprov->GetSSLStatus(getter_AddRefs(sslStatus));
    }
    nsAutoCString cipher;
    sslStatus->GetCipherName(cipher);
    fprintf(stderr, "GECKO CALLING MOZQUIC_HANDSHAKE_COMPLETE %s\n",
            cipher.get());

    PRFileDesc *fd;
    mPSMSSLSocketControl->GetNssFD(&fd);
    
    
    struct mozquic_handshake_info TODO;
    mozquic_handshake_complete(mSession, MOZQUIC_OK, &TODO);
    mHandshakeCompleteCode = MOZQUIC_OK;
  }

  uint32_t code = mozquic_IO(mSession);
  if (NS_SUCCEEDED(rv) && (code != MOZQUIC_OK)) {
    rv = NS_ERROR_FAILURE;
  }
  return rv;
}

int
QuicSession::MozQuicHandshakeCallback(void *closure,
                                      unsigned char *data, uint32_t len)
{
  QuicSession *self = reinterpret_cast<QuicSession *>(closure);
  // feed this data to PSM as it is the server reply
  // that has to be pulled via recv(mPSMHelper)
  // do so by storing in the pipe/buffer and waiting for recv
  uint32_t amt = 0;

  while (len > 0) {
    if (NS_FAILED(self->mPSMBufferOutput->Write((const char *)data, len, &amt))) {
      return MOZQUIC_ERR_GENERAL;
    }
    len -= amt;
    data += amt;
  }

  return MOZQUIC_OK;
}

int
QuicSession::NSPRWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  // someone has written to this FD. this should just assert and return a failure
  // todo
  // to fix we need a nsAHttpTransaction object (probably this object!) that
  // acts as a session layer instead of http2session which is what is goig on now
  //
  // ffor the time being, just drop the data and pretend we wrote it
  fprintf(stderr,"WARNING H2 Data written directly to QUIC Session FD\n");
  return aAmount;
}

int
QuicSession::NSPRSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                      int , PRIntervalTime)
{
  return NSPRWrite(aFD, aBuf, aAmount);
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

PRStatus
QuicSession::NSPRGetPeerName(PRFileDesc *aFD, PRNetAddr *addr)
{
  memset(addr,0,sizeof(*addr));
  addr->raw.family = PR_AF_INET;
  return PR_SUCCESS;
}

PRStatus
QuicSession::NSPRGetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt)
{
  if (aOpt->option == PR_SockOpt_Nonblocking) {
    aOpt->value.non_blocking = PR_TRUE;
    return PR_SUCCESS;
  }
  return PR_FAILURE;
}

PRStatus
QuicSession::NSPRSetSocketOption(PRFileDesc *fd, const PRSocketOptionData *data)
{
  return PR_FAILURE;
}

void
QuicSession::SetMethods(PRIOMethods *quicMethods, PRIOMethods *psmHelperMethods)
{
  if (quicMethods) {
    quicMethods->connect = NSPRConnect;
    quicMethods->close =   NSPRClose;
    quicMethods->send =    NSPRSend;
    quicMethods->write =   NSPRWrite;
  }
  if (psmHelperMethods) {
    // ssl stack triggers getpeername and default impl asserts(false)
    psmHelperMethods->getpeername = NSPRGetPeerName;
    psmHelperMethods->getsocketoption = NSPRGetSocketOption;
    psmHelperMethods->setsocketoption = NSPRSetSocketOption;
    psmHelperMethods->connect = psmHelperConnect;
    psmHelperMethods->write = psmHelperWrite;
    psmHelperMethods->send = psmHelperSend;
    psmHelperMethods->recv = psmHelperRecv;
    psmHelperMethods->read = psmHelperRead;
    psmHelperMethods->close = psmHelperClose;
  }
}

int
QuicSession::psmHelperWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  // client handshake data has come from psm and needs to be written into mozquic library
  // to be placed onto the wire as quic stream 0
  QuicSession *self = reinterpret_cast<QuicSession *>(fd->secret);
  mozquic_handshake_output(self->mSession, (unsigned char *)aBuf, aAmount);
  return aAmount;
}

int
QuicSession::psmHelperSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                           int , PRIntervalTime)
{
  return psmHelperWrite(aFD, aBuf, aAmount);
}

int32_t
QuicSession::psmHelperRead(PRFileDesc *fd, void *buf, int32_t amount)
{
  // psm is asking to read any data that has been provided from the mozquic
  // library off the network on stream 0. We keep that in the pipe buffer and it
  // was written there during MozQuicHandshakeCallback()
  uint32_t count = 0;
  QuicSession *self = reinterpret_cast<QuicSession *>(fd->secret);
  nsresult rv = self->mPSMBufferInput->Read((char *)buf, amount, &count);
  if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
  return count;
}

int32_t
QuicSession::psmHelperRecv(PRFileDesc *fd, void *buf, int32_t amount, int flags,
                           PRIntervalTime timeout)
{
  return psmHelperRead(fd, buf, amount);
}
  
PRStatus
QuicSession::psmHelperConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  return PR_SUCCESS;
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

  // todo - I don't think this is necessary, I think the send/recv
  // callbacks can be used instead
  mozquic_setosfd(self->mSession, PR_FileDesc2NativeHandle(fd));
  if (mozquic_start_connection(self->mSession) != MOZQUIC_OK) {
    return PR_FAILURE;
  }

  return PR_SUCCESS;
}

PRStatus
QuicSession::psmHelperClose(PRFileDesc *fd)
{
  QuicSession *self = reinterpret_cast<QuicSession *>(fd->secret);
  delete self;
  return PR_SUCCESS;
}

// nsISSLSocketControl
// todo most of these just get forwarded

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

NS_IMETHODIMP QuicSession::SetNPNList(nsTArray<nsCString> & aList)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->SetNPNList(aList);
}

NS_IMETHODIMP
QuicSession::GetNssFD(PRFileDesc **outFD)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetNssFD(outFD);
}

/* readonly attribute ACString negotiatedNPN; */
NS_IMETHODIMP QuicSession::GetNegotiatedNPN(nsACString & aNegotiatedNPN)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  nsresult rv = mPSMSSLSocketControl->GetNegotiatedNPN(aNegotiatedNPN);
  if (NS_SUCCEEDED(rv) && mHandshakeCompleteCode != MOZQUIC_OK){
    // todo mvp - this means we need 2 rtt
    // temporarily here to avoid dtor of session too early
    rv = NS_ERROR_NOT_CONNECTED;
  }
  return rv;
}

/* [infallible] readonly attribute short SSLVersionUsed; */
NS_IMETHODIMP QuicSession::GetSSLVersionUsed(int16_t *aSSLVersionUsed)
{
  if (mHandshakeCompleteCode == MOZQUIC_OK) {
    *aSSLVersionUsed = nsISSLSocketControl::TLS_VERSION_1_3;
  } else {
    *aSSLVersionUsed = nsISSLSocketControl::SSL_VERSION_UNKNOWN;
  }
  return NS_OK;
}

/* [infallible] readonly attribute short KEAUsed; */
NS_IMETHODIMP QuicSession::GetKEAUsed(int16_t *aKEAUsed)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetKEAUsed(aKEAUsed);
}

/* [infallible] readonly attribute unsigned long KEAKeyBits; */
NS_IMETHODIMP QuicSession::GetKEAKeyBits(uint32_t *aKEAKeyBits)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetKEAKeyBits(aKEAKeyBits);
}

/* [infallible] readonly attribute boolean bypassAuthentication; */
NS_IMETHODIMP QuicSession::GetBypassAuthentication(bool *aBypassAuthentication)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  nsresult rv = mPSMSSLSocketControl->GetBypassAuthentication(aBypassAuthentication);
  MOZ_ASSERT(NS_FAILED(rv) || !(*aBypassAuthentication));
  return rv;
}

/* [infallible] readonly attribute boolean failedVerification; */
NS_IMETHODIMP QuicSession::GetFailedVerification(bool *aFailedVerification)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetFailedVerification(aFailedVerification);
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

/* [infallible] readonly attribute short SSLVersionOffered; */
NS_IMETHODIMP QuicSession::GetSSLVersionOffered(int16_t *aSSLVersionOffered)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetSSLVersionOffered(aSSLVersionOffered);
}

/* [infallible] readonly attribute short MACAlgorithmUsed; */
NS_IMETHODIMP QuicSession::GetMACAlgorithmUsed(int16_t *aMACAlgorithmUsed)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetMACAlgorithmUsed(aMACAlgorithmUsed);
}

/* attribute nsIX509Cert clientCert; */
NS_IMETHODIMP QuicSession::GetClientCert(nsIX509Cert * *aClientCert)
{
  return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP QuicSession::SetClientCert(nsIX509Cert *aClientCert)
{
  return NS_ERROR_NOT_IMPLEMENTED;
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

/* readonly attribute uint32_t providerFlags; */
NS_IMETHODIMP QuicSession::GetProviderFlags(uint32_t *aProviderFlags)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMPL_ISUPPORTS(QuicSession, nsISSLSocketControl)

bool
QuicSessionUtil::IsQuicSession(PRFileDesc *fd)
{
  if (!psmHelperIdentity) {
    return false;
  }
  if (fd->identity == psmHelperIdentity) {
    return true;
  }
  if (fd->lower) {
    return IsQuicSession(fd->lower);
  }
  return false;
}

} } // namespace mozilla::net


