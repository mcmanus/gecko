/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "NSSHelper.h"
#include "nss.h"
#include "ssl.h"
#include "sslproto.h"
#include "cert.h"
#include "certdb.h"
#include "pk11pub.h"
#include "assert.h"

namespace mozilla { namespace net {
        
static bool mozQuicInit = false;
static PRDescIdentity nssHelperIdentity;
static PRIOMethods nssHelperMethods;
  
int
NSSHelper::Init(char *dir)
{
  if (mozQuicInit) {
    return MOZQUIC_ERR_GENERAL;
  }
  mozQuicInit = true;
  nssHelperIdentity = PR_GetUniqueIdentity("nssHelper");
  nssHelperMethods = *PR_GetDefaultIOMethods();

  nssHelperMethods.getpeername = NSPRGetPeerName;
  nssHelperMethods.getsocketoption = NSPRGetSocketOption;
  nssHelperMethods.connect = nssHelperConnect;
  nssHelperMethods.write = nssHelperWrite;
  nssHelperMethods.send = nssHelperSend;
  nssHelperMethods.recv = nssHelperRecv;
  nssHelperMethods.read = nssHelperRead;

  return (NSS_Init(dir) == SECSuccess) ? MOZQUIC_OK : MOZQUIC_ERR_GENERAL;
}
  
NSSHelper::NSSHelper(MozQuic *quicSession, const char *originKey)
  : mQuicSession(quicSession)
  , mReady(false)
{
  PRNetAddr addr;
  memset(&addr,0,sizeof(addr));
  addr.raw.family = PR_AF_INET;

  mFD = PR_CreateIOLayerStub(nssHelperIdentity, &nssHelperMethods);
  mFD->secret = (struct PRFilePrivate *)this;
  mFD = SSL_ImportFD(nullptr, mFD);
  SSL_OptionSet(mFD, SSL_SECURITY, true);
  SSL_OptionSet(mFD, SSL_HANDSHAKE_AS_CLIENT, false);
  SSL_OptionSet(mFD, SSL_HANDSHAKE_AS_SERVER, true);
  SSL_OptionSet(mFD, SSL_ENABLE_RENEGOTIATION, SSL_RENEGOTIATE_NEVER);
  SSL_OptionSet(mFD, SSL_NO_CACHE, true);
  SSL_OptionSet(mFD, SSL_ENABLE_SESSION_TICKETS, true);
  SSL_OptionSet(mFD, SSL_REQUEST_CERTIFICATE, false);
  SSL_OptionSet(mFD, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);

  SSLVersionRange range = {SSL_LIBRARY_VERSION_TLS_1_3,
                           SSL_LIBRARY_VERSION_TLS_1_3};
  SSL_VersionRangeSet(mFD, &range);

  CERTCertificate *cert =
    CERT_FindCertByNickname(CERT_GetDefaultCertDB(), originKey);
  if (cert) {
    SECKEYPrivateKey *key = PK11_FindKeyByAnyCert(cert, nullptr);
    if (key) {
      SECStatus rv = SSL_ConfigServerCert(mFD, cert, key, nullptr, 0);
      if (rv == SECSuccess) {
        mReady = true;
      }
    }
  }
    
  PR_Connect(mFD, &addr, 0);
  // if you Read() from the helper, it pulls through the tls layer from the mozquic::stream0 buffer where
  // peer data lke the client hello is stored.. if you Write() to the helper something
  // like "", the tls layer adds the server hello on the way out into mozquic::stream0

}


int
NSSHelper::nssHelperWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  // data (e.g. server hello) has come from nss and needs to be written into MozQuic
  // to be written out to the network in stream 0
  NSSHelper *self = reinterpret_cast<NSSHelper *>(fd->secret);
  self->mQuicSession->NSSOutput(aBuf, aAmount);
  return aAmount;
}

int
NSSHelper::nssHelperSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                           int , PRIntervalTime)
{
  return nssHelperWrite(aFD, aBuf, aAmount);
}

int32_t
NSSHelper::nssHelperRead(PRFileDesc *fd, void *buf, int32_t amount)
{
  // nss is asking for input, i.e. a client hello from stream 0 after
  // stream reassembly
  NSSHelper *self = reinterpret_cast<NSSHelper *>(fd->secret);
  return self->mQuicSession->NSSInput(buf, amount);
}

int32_t
NSSHelper::nssHelperRecv(PRFileDesc *fd, void *buf, int32_t amount, int flags,
                           PRIntervalTime timeout)
{
  return nssHelperRead(fd, buf, amount);
}

PRStatus
NSSHelper::NSPRGetPeerName(PRFileDesc *aFD, PRNetAddr *addr)
{
  memset(addr,0,sizeof(*addr));
  addr->raw.family = PR_AF_INET;
  return PR_SUCCESS;
}

PRStatus
NSSHelper::NSPRGetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt)
{
  if (aOpt->option == PR_SockOpt_Nonblocking) {
    aOpt->value.non_blocking = PR_TRUE;
    return PR_SUCCESS;
  }
  return PR_FAILURE;
}

PRStatus
NSSHelper::nssHelperConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  return PR_SUCCESS;
}

uint32_t
NSSHelper::DriveHandShake()
{
  assert(mReady);// todo
  if (!mReady) {
    return MOZQUIC_ERR_GENERAL;
  }
  char data[1024];

  PR_Read(mFD, data, 1024);
  return MOZQUIC_OK;
}

}}
