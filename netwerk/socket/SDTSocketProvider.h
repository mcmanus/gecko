/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef SDTSocketProvider_h__
#define SDTSocketProvider_h__

#pragma once
#include "mozilla/Attributes.h"
#include "nsISocketProvider.h"

#define NS_SDTSOCKETPROVIDER_CID { 0xf7c9f5f4, 0x4451, 0x41c3, { 0xa2, 0x8a, 0x5b, 0xb2, 0x4f, 0x7f, 0xba, 0xce } }

namespace mozilla { namespace net {

class SDTSocketProvider final : public nsISocketProvider
{
public:
    NS_DECL_THREADSAFE_ISUPPORTS
    NS_DECL_NSISOCKETPROVIDER

    SDTSocketProvider();
private:
    ~SDTSocketProvider();
};

} } // namespace mozilla::net

#endif /* SDTSocketProvider_h__ */

