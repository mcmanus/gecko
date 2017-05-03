/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef QuicSocketProvider_h__
#define QuicSocketProvider_h__

#pragma once
#include "mozilla/Attributes.h"
#include "nsISocketProvider.h"

#define NS_QUICSOCKETPROVIDER_CID { 0xf7c9f5f4, 0x4451, 0x41c3, { 0xa2, 0x8a, 0x5b, 0xb2, 0x4f, 0x7f, 0xba, 0xce } }

namespace mozilla { namespace net {

class QuicSocketProvider final : public nsISocketProvider
{
public:
    NS_DECL_THREADSAFE_ISUPPORTS
    NS_DECL_NSISOCKETPROVIDER

    QuicSocketProvider();
private:
    ~QuicSocketProvider();
};

} } // namespace mozilla::net

#endif /* QuicSocketProvider_h__ */

