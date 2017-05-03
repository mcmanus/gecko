/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "QuicSession.h"

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

} } // namespace mozilla::net


