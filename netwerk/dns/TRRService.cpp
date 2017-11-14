/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/net/TRRService.h"
#include "mozilla/Services.h"
#include "mozilla/Preferences.h"
#include "nsIObserverService.h"
#include "nsServiceManagerUtils.h"

namespace mozilla {
namespace net {

static LazyLogModule gTRRLog("TRR");
#undef LOG
#define LOG(args) MOZ_LOG(gTRRLog, mozilla::LogLevel::Debug, args)

TRRService *gTRRService = nullptr;

NS_IMPL_ISUPPORTS(TRRService, nsIObserver)

TRRService::TRRService()
: mInitialized(false)
{

}

nsresult
TRRService::Init()
{
    if (mInitialized) {
        return NS_OK;
    }
    mInitialized = true;
    gTRRService = this;
    return NS_OK;
}

nsresult
TRRService::Start()
{
    if (!mInitialized) {
        return NS_ERROR_NOT_INITIALIZED;
    }
    return NS_OK;
}

nsresult
TRRService::Stop()
{
    return NS_OK;
}

TRRService::~TRRService()
{
    LOG(("Exiting TRRService\n"));
    gTRRService = nullptr;
}

NS_IMETHODIMP
TRRService::Observe(nsISupports *aSubject,
                    const char * aTopic,
                    const char16_t * aData)
{
    return NS_OK;
}

nsresult
TRRServiceConstructor(nsISupports *aOuter, REFNSIID aIID, void **aResult)
{
    fprintf(stderr, "\n\n---------------\n TRRServiceConstructor\n----------------\n\n");
    return NS_OK;
}

} // namespace net
} // namespace mozilla
