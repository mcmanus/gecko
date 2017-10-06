/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Assertions.h"
#include "MozQuic.h"
#include "QuicSocket.h"
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
#include "QuicSocketUtil.h"
#include "nsISSLStatusProvider.h"
#include "nsISSLStatus.h"
#include "nsHttpHandler.h"

#include "ssl.h"
#include "sslproto.h"

namespace mozilla { namespace net {

static bool quicInit = false;
static PRDescIdentity quicIdentity, psmHelperIdentity;
static PRIOMethods quicMethods, psmHelperMethods;

NS_IMPL_ISUPPORTS(QuicSocket, nsISSLSocketControl, nsISSLStatusProvider)

QuicSocket::QuicSocket(const char *host, int32_t port, bool v4)
  : mClosed(false)
  , mDestroyOnClose(false)
  , mQuicConnected(false)
  , mTransportParamsToWriteLen(0)
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
  config.appHandlesSendRecv = 1; // flag to control TRANSMIT/RECV/TLSINPUT events

// todo deal with failures
  mozquic_new_connection(&mSession, &config);
  mozquic_set_event_callback_closure(mSession, this);
  mozquic_set_event_callback(mSession, MozQuicEventCallback);
 
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
                        OriginAttributes(), 0, 0, mPSMHelper,
                        getter_AddRefs(mPSMHelperSecInfo));
    
  mPSMSSLSocketControl = do_QueryInterface(mPSMHelperSecInfo);
  PRNetAddr addr;
  memset(&addr,0,sizeof(addr));
  addr.raw.family = PR_AF_INET;

  
  PRFileDesc *nss;
  mPSMSSLSocketControl->GetNssFD(&nss);
  static const uint32_t kTransportParametersID = 26; // todo
  SSLExtensionSupport supportTransportParameters;
  if (SSL_GetExtensionSupport(kTransportParametersID, &supportTransportParameters) == SECSuccess &&  
      supportTransportParameters != ssl_ext_native_only &&
      SSL_InstallExtensionHooks(nss, kTransportParametersID,
                                TransportExtensionWriter, this,
                                TransportExtensionHandler, this) == SECSuccess) {
    PR_Connect(mPSMHelper, &addr, 0);
  } else {
    MOZ_ASSERT(false);
  }

  Unused << NS_NewPipe2(getter_AddRefs(mPSMBufferInput),
                        getter_AddRefs(mPSMBufferOutput),
                        true, true, 0, UINT32_MAX);
}

void
QuicSocket::IO()
{
  if (mSession) {
    mozquic_IO(mSession);
  }
}

QuicSocket *
QuicSocket::GetFromFD(PRFileDesc *fd)
{
  if (!quicInit) {
    return nullptr;
  }

  if (fd->identity == quicIdentity) {
    return reinterpret_cast<QuicSocket *>(fd->secret);
  }

  if (fd->lower) {
    return GetFromFD(fd->lower);
  }

  return nullptr;
}
  
QuicSocket::~QuicSocket()
{
  fprintf(stderr,"QuicSocket::~QuicSocket %p\n", this);
  if (!OnSocketThread()) {
    fprintf (stderr,"todo shutdown leak\n");
    mSession = nullptr;
    mFD = nullptr;
    mPSMHelper = nullptr;
  } else {
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
}

mozquic_stream_t *
QuicSocket::NewStream()
{
  if (!mSession) {
    return nullptr;
  }
  mozquic_stream_t *stream;
  int code = mozquic_start_new_stream(&stream, mSession, nullptr, 0, 0);
  if (code != MOZQUIC_OK) {
    return nullptr;
  }
  return stream;
}

NS_IMETHODIMP
QuicSocket::GetSSLStatus(nsISSLStatus * *aSSLStatus)
{
  nsCOMPtr<nsISSLStatusProvider> sslprov = do_QueryInterface(mPSMHelperSecInfo);
  if (sslprov) {
    return sslprov->GetSSLStatus(aSSLStatus);
  }
  return NS_ERROR_FAILURE;
}

NS_IMETHODIMP
QuicSocket::DriveHandshake()
{
  if (mQuicConnected) {
    return NS_OK;
  }
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
    if (NS_SUCCEEDED(sslStatus->GetCipherName(cipher))) {
      fprintf(stderr, "GECKO CALLING MOZQUIC_HANDSHAKE_COMPLETE %s\n", cipher.get());
    }

    struct mozquic_handshake_info handshakeinfo;
    PRFileDesc *fd;
    mPSMSSLSocketControl->GetNssFD(&fd);

    uint32_t secretSize;
    if (!strcmp("TLS_AES_128_GCM_SHA256", cipher.get())) {
      secretSize = 32;
      handshakeinfo.ciphersuite = MOZQUIC_AES_128_GCM_SHA256;
    } else if (!strcmp("TLS_AES_256_GCM_SHA384", cipher.get())) {
      secretSize = 48;
      handshakeinfo.ciphersuite = MOZQUIC_AES_256_GCM_SHA384;
    } else if (!strcmp("TLS_CHACHA20_POLY1305_SHA256", cipher.get())) {
      secretSize = 32;
      handshakeinfo.ciphersuite = MOZQUIC_CHACHA20_POLY1305_SHA256;
    } else {
      return NS_ERROR_FAILURE;
    }

    if (SSL_ExportKeyingMaterial(fd, "EXPORTER-QUIC client 1-RTT Secret", strlen("EXPORTER-QUIC client 1-RTT Secret"),
                                 false, (const unsigned char *)"", 0, handshakeinfo.sendSecret, secretSize) != SECSuccess) {
      return NS_ERROR_FAILURE;
    }

    if (SSL_ExportKeyingMaterial(fd, "EXPORTER-QUIC server 1-RTT Secret", strlen("EXPORTER-QUIC server 1-RTT Secret"),
                                 false, (const unsigned char *)"", 0, handshakeinfo.recvSecret, secretSize) != SECSuccess) {
      return NS_ERROR_FAILURE;
    }

    uint32_t code = mozquic_handshake_complete(mSession, MOZQUIC_OK, &handshakeinfo);
    MOZ_ASSERT(code == MOZQUIC_OK);
    mHandshakeCompleteCode = MOZQUIC_OK;
  }

  uint32_t code = mozquic_IO(mSession);
  if (NS_SUCCEEDED(rv) && (code != MOZQUIC_OK)) {
    rv = NS_ERROR_FAILURE;
  }
  return rv;
}

int
QuicSocket::MozQuicEventCallback(void *closure, uint32_t event, void *param)
{
  QuicSocket *self = reinterpret_cast<QuicSocket *>(closure);
  switch (event) {
  case MOZQUIC_EVENT_TLSINPUT:
  {
    struct mozquic_eventdata_tlsinput *input =
      reinterpret_cast<struct mozquic_eventdata_tlsinput *>(param);
    return self->MozQuicHandshakeCallback(input->data, input->len);
  }
  case MOZQUIC_EVENT_TLS_CLIENT_TPARAMS:
  {
    struct mozquic_eventdata_tlsinput *input =
      reinterpret_cast<struct mozquic_eventdata_tlsinput *>(param);
    self->mTransportParamsToWrite = MakeUnique<unsigned char[]>(input->len);
    self->mTransportParamsToWriteLen = input->len;
    memcpy(self->mTransportParamsToWrite.get(), input->data, input->len);
    return MOZQUIC_OK;
  }
  case MOZQUIC_EVENT_TRANSMIT:
  {
    if (!self->mFD) {
      return MOZQUIC_ERR_IO;
    }
    struct mozquic_eventdata_transmit *input =
      reinterpret_cast<struct mozquic_eventdata_transmit *>(param);
    PR_Write(self->mFD->lower, input->pkt, input->len);
    return MOZQUIC_OK;
  }
  case MOZQUIC_EVENT_RECV:
  {
    if (!self->mFD) {
      return MOZQUIC_ERR_IO;
    }
    struct mozquic_eventdata_recv *input =
      reinterpret_cast<struct mozquic_eventdata_recv *>(param);
    int consumed = PR_Read(self->mFD->lower, input->pkt, input->avail);
    if (consumed >= 0) {
      *input->written = consumed;
      return MOZQUIC_OK;
    } else {
      return MOZQUIC_ERR_IO;
    }
  }
    break;
  case MOZQUIC_EVENT_CONNECTED:
    self->mQuicConnected = true;
    break;
  case MOZQUIC_EVENT_IO:
  case MOZQUIC_EVENT_LOG:
    break;

  case MOZQUIC_EVENT_NEW_STREAM_DATA:
    self->mConnection->ForceRecv();
    break;

  default:
    MOZ_ASSERT(false);
  }
  
  return MOZQUIC_OK;
}

int
QuicSocket::MozQuicHandshakeCallback(unsigned char *data, uint32_t len)
{
  // feed this data to PSM as it is the server reply
  // that has to be pulled via recv(mPSMHelper)
  // do so by storing in the pipe/buffer and waiting for recv
  uint32_t amt = 0;

  while (len > 0) {
    if (NS_FAILED(mPSMBufferOutput->Write((const char *)data, len, &amt))) {
      return MOZQUIC_ERR_GENERAL;
    }
    len -= amt;
    data += amt;
  }

  return MOZQUIC_OK;
}

PRBool
QuicSocket::TransportExtensionWriter(PRFileDesc *fd, SSLHandshakeType m,
                                      PRUint8 *data, unsigned int *len, unsigned int maxlen, void *arg)
{
  QuicSocket *self = reinterpret_cast<QuicSocket *>(arg);
  if (m != ssl_hs_client_hello && m != ssl_hs_encrypted_extensions) {
    return PR_FALSE;
  }
  if (maxlen < self->mTransportParamsToWriteLen) {
    return PR_FALSE;
  }

  memcpy(data, self->mTransportParamsToWrite.get(), self->mTransportParamsToWriteLen);
  *len = self->mTransportParamsToWriteLen;
  self->mTransportParamsToWrite = nullptr;
  self->mTransportParamsToWriteLen = 0;
  return PR_TRUE;
}

SECStatus
QuicSocket::TransportExtensionHandler(PRFileDesc *fd, SSLHandshakeType m, const PRUint8 *data,
                                       unsigned int len, SSLAlertDescription *alert, void *arg)
{
  QuicSocket *self = reinterpret_cast<QuicSocket *>(arg);
  if (m != ssl_hs_encrypted_extensions) {
    return SECSuccess;
  }

  mozquic_tls_tparam_output(self->mSession, data, len);
  return SECSuccess;
}

int
QuicSocket::NSPRWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
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
QuicSocket::NSPRSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                      int , PRIntervalTime)
{
  return NSPRWrite(aFD, aBuf, aAmount);
}

PRStatus
QuicSocket::NSPRClose(PRFileDesc *fd)
{
  QuicSocket *self = reinterpret_cast<QuicSocket *>(fd->secret);
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
QuicSocket::NSPRGetPeerName(PRFileDesc *aFD, PRNetAddr *addr)
{
  memset(addr,0,sizeof(*addr));
  addr->raw.family = PR_AF_INET;
  return PR_SUCCESS;
}

PRStatus
QuicSocket::NSPRGetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt)
{
  if (aOpt->option == PR_SockOpt_Nonblocking) {
    aOpt->value.non_blocking = PR_TRUE;
    return PR_SUCCESS;
  }
  return PR_FAILURE;
}

PRStatus
QuicSocket::NSPRSetSocketOption(PRFileDesc *fd, const PRSocketOptionData *data)
{
  return PR_FAILURE;
}

void
QuicSocket::SetMethods(PRIOMethods *quicMethods, PRIOMethods *psmHelperMethods)
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
QuicSocket::psmHelperWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  // client handshake data has come from psm and needs to be written into mozquic library
  // to be placed onto the wire as quic stream 0
  QuicSocket *self = reinterpret_cast<QuicSocket *>(fd->secret);
  if (!self->mFD || !self->mSession) {
    return aAmount;
  }
  mozquic_handshake_output(self->mSession, (unsigned char *)aBuf, aAmount);
  return aAmount;
}

int
QuicSocket::psmHelperSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                           int , PRIntervalTime)
{
  return psmHelperWrite(aFD, aBuf, aAmount);
}

int32_t
QuicSocket::psmHelperRead(PRFileDesc *fd, void *buf, int32_t amount)
{
  // psm is asking to read any data that has been provided from the mozquic
  // library off the network on stream 0. We keep that in the pipe buffer and it
  // was written there during MozQuicHandshakeCallback()
  uint32_t count = 0;
  QuicSocket *self = reinterpret_cast<QuicSocket *>(fd->secret);
  nsresult rv = self->mPSMBufferInput->Read((char *)buf, amount, &count);
  if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
  return count;
}

int32_t
QuicSocket::psmHelperRecv(PRFileDesc *fd, void *buf, int32_t amount, int flags,
                           PRIntervalTime timeout)
{
  return psmHelperRead(fd, buf, amount);
}
  
PRStatus
QuicSocket::psmHelperConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  return PR_SUCCESS;
}

PRStatus
QuicSocket::NSPRConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  QuicSocket *self = reinterpret_cast<QuicSocket *>(fd->secret);
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
  if (mozquic_start_client(self->mSession) != MOZQUIC_OK) {
    return PR_FAILURE;
  }

  return PR_SUCCESS;
}

PRStatus
QuicSocket::psmHelperClose(PRFileDesc *fd)
{
  QuicSocket *self = reinterpret_cast<QuicSocket *>(fd->secret);
  if (self->mFD) {
    delete self;
  }
  return PR_SUCCESS;
}

// nsISSLSocketControl
// todo most of these just get forwarded

/* attribute nsIInterfaceRequestor notificationCallbacks; */
NS_IMETHODIMP QuicSocket::GetNotificationCallbacks(nsIInterfaceRequestor * *aNotificationCallbacks)
{
  nsCOMPtr<nsIInterfaceRequestor> rv(mCallbacks);
  *aNotificationCallbacks = rv.forget().take();
  return NS_OK;
}
NS_IMETHODIMP QuicSocket::SetNotificationCallbacks(nsIInterfaceRequestor *aNotificationCallbacks)
{
  mCallbacks = aNotificationCallbacks;
  return NS_OK;
}

NS_IMETHODIMP QuicSocket::SetNPNList(nsTArray<nsCString> & aList)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->SetNPNList(aList);
}

NS_IMETHODIMP
QuicSocket::GetNssFD(PRFileDesc **outFD)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetNssFD(outFD);
}

/* readonly attribute ACString negotiatedNPN; */
NS_IMETHODIMP QuicSocket::GetNegotiatedNPN(nsACString & aNegotiatedNPN)
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
NS_IMETHODIMP QuicSocket::GetSSLVersionUsed(int16_t *aSSLVersionUsed)
{
  if (mHandshakeCompleteCode == MOZQUIC_OK) {
    *aSSLVersionUsed = nsISSLSocketControl::TLS_VERSION_1_3;
  } else {
    *aSSLVersionUsed = nsISSLSocketControl::SSL_VERSION_UNKNOWN;
  }
  return NS_OK;
}

/* [infallible] readonly attribute short KEAUsed; */
NS_IMETHODIMP QuicSocket::GetKEAUsed(int16_t *aKEAUsed)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetKEAUsed(aKEAUsed);
}

/* [infallible] readonly attribute unsigned long KEAKeyBits; */
NS_IMETHODIMP QuicSocket::GetKEAKeyBits(uint32_t *aKEAKeyBits)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetKEAKeyBits(aKEAKeyBits);
}

/* [infallible] readonly attribute boolean bypassAuthentication; */
NS_IMETHODIMP QuicSocket::GetBypassAuthentication(bool *aBypassAuthentication)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  nsresult rv = mPSMSSLSocketControl->GetBypassAuthentication(aBypassAuthentication);
  MOZ_ASSERT(NS_FAILED(rv) || !(*aBypassAuthentication));
  return rv;
}

/* [infallible] readonly attribute boolean failedVerification; */
NS_IMETHODIMP QuicSocket::GetFailedVerification(bool *aFailedVerification)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetFailedVerification(aFailedVerification);
}

/* void proxyStartSSL (); */
NS_IMETHODIMP QuicSocket::ProxyStartSSL()
{
  return NS_OK;
}

/* void StartTLS (); */
NS_IMETHODIMP QuicSocket::StartTLS()
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* ACString getAlpnEarlySelection (); */
NS_IMETHODIMP QuicSocket::GetAlpnEarlySelection(nsACString & _retval)
{
  // need to get historic data from nss
  // todo
  return NS_ERROR_NOT_AVAILABLE;
}

/* readonly attribute bool earlyDataAccepted; */
NS_IMETHODIMP QuicSocket::GetEarlyDataAccepted(bool *aEarlyDataAccepted)
{
  // todo
  *aEarlyDataAccepted = false;
  return NS_OK;
}

/* [infallible] readonly attribute short SSLVersionOffered; */
NS_IMETHODIMP QuicSocket::GetSSLVersionOffered(int16_t *aSSLVersionOffered)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetSSLVersionOffered(aSSLVersionOffered);
}

/* [infallible] readonly attribute short MACAlgorithmUsed; */
NS_IMETHODIMP QuicSocket::GetMACAlgorithmUsed(int16_t *aMACAlgorithmUsed)
{
  if (!mPSMSSLSocketControl) {
    return NS_ERROR_UNEXPECTED;
  }
  return mPSMSSLSocketControl->GetMACAlgorithmUsed(aMACAlgorithmUsed);
}

/* attribute nsIX509Cert clientCert; */
NS_IMETHODIMP QuicSocket::GetClientCert(nsIX509Cert * *aClientCert)
{
  return NS_ERROR_NOT_IMPLEMENTED;
}

NS_IMETHODIMP QuicSocket::SetClientCert(nsIX509Cert *aClientCert)
{
  return NS_ERROR_NOT_IMPLEMENTED;
}

/* boolean joinConnection (in ACString npnProtocol, in ACString hostname, in long port); */
NS_IMETHODIMP QuicSocket::JoinConnection(const nsACString & npnProtocol, const nsACString & hostname, int32_t port, bool *_retval)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* boolean testJoinConnection (in ACString npnProtocol, in ACString hostname, in long port); */
NS_IMETHODIMP QuicSocket::TestJoinConnection(const nsACString & npnProtocol, const nsACString & hostname, int32_t port, bool *_retval)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* boolean isAcceptableForHost (in ACString hostname); */
NS_IMETHODIMP QuicSocket::IsAcceptableForHost(const nsACString & hostname, bool *_retval)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* readonly attribute uint32_t providerFlags; */
NS_IMETHODIMP QuicSocket::GetProviderFlags(uint32_t *aProviderFlags)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

/* readonly attribute uint32_t providerFlags; */
NS_IMETHODIMP QuicSocket::GetProviderTlsFlags(uint32_t *aProviderFlags)
{
    /* TODO PRM */ MOZ_ASSERT(false); return NS_ERROR_NOT_IMPLEMENTED;
}

bool
QuicSocketUtil::IsQuicSocket(PRFileDesc *fd)
{
  if (!psmHelperIdentity) {
    return false;
  }
  if (fd->identity == psmHelperIdentity) {
    return true;
  }
  if (fd->lower) {
    return IsQuicSocket(fd->lower);
  }
  return false;
}

} } // namespace mozilla::net


