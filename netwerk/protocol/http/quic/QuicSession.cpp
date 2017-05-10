/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Assertions.h"
#include "QuicSession.h"
#include <sys/socket.h>

namespace mozilla { namespace net {

QuicSession::QuicSession(PRFileDesc *fd, mozquic_connection_t *session)
  : mClosed(false)
  , mDestroyOnClose(true)
  , mFD(fd)
  , mSession(session)
{
  fd->secret = (struct PRFilePrivate *)this;
}

QuicSession::~QuicSession()
{
  if (mSession) {
    mozquic_destroy_connection(mSession);
  }

  if (mFD) {
    PR_Close(mFD);
  }
  mFD->secret = nullptr;
}

PRStatus
QuicSession::NSPRClose(PRFileDesc *fd)
{
  QuicSession *self = reinterpret_cast<QuicSession *>(fd->secret);
  self->mClosed = true;
  if (self->mDestroyOnClose) {
    delete self;
  }
  return PR_SUCCESS;
}

void
QuicSession::SetMethods(PRIOMethods *outMethods)
{
  if (!outMethods) {
    return;
  }
  outMethods->connect = NSPRConnect;
  outMethods->close =   NSPRClose;
  outMethods->setsocketoption = NSPRSetSockOpt;
  outMethods->getsockname = NSPRGetSockName;
}

PRStatus
QuicSession::NSPRConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  QuicSession *self = reinterpret_cast<QuicSession *>(fd->secret);
  if (!self || self->mClosed || !self->mSession) {
    return PR_FAILURE;
  }
  if (mozquic_start_connection(self->mSession) != MOZQUIC_OK) {
    return PR_FAILURE;
  }

  return PR_SUCCESS;
}

PRStatus
QuicSession::NSPRSetSockOpt(PRFileDesc *fd, const PRSocketOptionData *opt)
{
  // todo?
  return PR_SUCCESS;
}

PRStatus
QuicSession::NSPRGetSockName(PRFileDesc *fd, PRNetAddr *outAddr)
{
  QuicSession *self = reinterpret_cast<QuicSession *>(fd->secret);
  if (!self || self->mClosed || !self->mSession) {
    return PR_FAILURE;
  }
  int udp = mozquic_osfd(self->mSession);
  struct sockaddr_in6 real, *v6;
  struct sockaddr_in  *v4;
  struct sockaddr     *addr;
  socklen_t addrlen;

  addr = reinterpret_cast<struct sockaddr *>(&real);
  v4   = reinterpret_cast<struct sockaddr_in *>(&real);
  v6   = &real;
  addrlen = sizeof (real);
  
  getsockname(udp, addr, &addrlen);
  if (addrlen == sizeof (struct sockaddr_in6)) {
    outAddr->ipv6.family = PR_AF_INET6;
    outAddr->ipv6.port = v6->sin6_port;
    memcpy(&outAddr->ipv6.ip, &v6->sin6_addr, sizeof (PRIPv6Addr));
  } else {
    MOZ_ASSERT(addrlen == sizeof(struct sockaddr_in));
    outAddr->inet.family = PR_AF_INET;
    outAddr->inet.port = v4->sin_port;
    memcpy(&outAddr->inet.ip, &v4->sin_addr, sizeof (PRUint32));
  }
  return PR_SUCCESS;
}

} } // namespace mozilla::net


