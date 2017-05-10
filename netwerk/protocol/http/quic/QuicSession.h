/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef QuicSession_h__
#define QuicSession_h__

#pragma once

#include "nspr.h"
#include "MozQuic.h"

namespace mozilla { namespace net {

class QuicSession final
{
public:
    QuicSession(PRFileDesc *fd, mozquic_connection_t *session);

    static PRStatus NSPRConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to);
    static PRStatus NSPRClose(PRFileDesc *fd);
    static PRStatus NSPRSetSockOpt(PRFileDesc *fd, const PRSocketOptionData *opt);
    static PRStatus NSPRGetSockName(PRFileDesc *fd, PRNetAddr *addr);
    static void SetMethods(PRIOMethods *outMethods);

private:
    ~QuicSession();

    bool         mClosed;
    bool         mDestroyOnClose;
    PRFileDesc  *mFD;
    mozquic_connection_t *mSession;
};

} } // namespace mozilla::net

#endif /* QuicSocketProvider_h__ */

