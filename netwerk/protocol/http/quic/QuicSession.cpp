/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Assertions.h"
#include "QuicSession.h"
#include <sys/socket.h>

namespace mozilla { namespace net {

  QuicSession::QuicSession(PRFileDesc *fd, mozquic_connection_t *session,
                           mozquic_config_t *config)
  : mClosed(false)
  , mDestroyOnClose(true)
  , mFD(fd)
  , mSession(session)
{
  fd->secret = (struct PRFilePrivate *)this;

  PRFileDesc *udpLayer =
    PR_OpenUDPSocket(config->domain == AF_INET ? PR_AF_INET : PR_AF_INET6);
  PR_PushIOLayer(udpLayer, PR_GetLayersIdentity(udpLayer), fd);
  MOZ_ASSERT(!config->handleIO);
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
QuicSession::SetMethods(PRIOMethods *outMethods)
{
  if (!outMethods) {
    return;
  }
  outMethods->connect = NSPRConnect;
  outMethods->close =   NSPRClose;
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

  
} } // namespace mozilla::net


