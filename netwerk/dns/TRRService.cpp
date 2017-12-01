/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/net/TRRService.h"
#include "mozilla/Services.h"
#include "mozilla/Preferences.h"
#include "nsIObserverService.h"
#include "nsServiceManagerUtils.h"

static const char kCaptivePortalLoginSuccessEvent[] = "captive-portal-login-success";
static const char kCaptivePortalLoginEvent[] = "captive-portal-login";

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

    nsCOMPtr<nsIObserverService> observerService =
      mozilla::services::GetObserverService();
    if (observerService) {
        observerService->AddObserver(this, kCaptivePortalLoginEvent, true);
        observerService->AddObserver(this, kCaptivePortalLoginSuccessEvent, true);
    }

    // 0 - parallel, 1 TRR first, 2 TRR only, ...
    Preferences::GetUint("network.trr.mode", &mMode);

    // Base URI, appends "?body=..."
    Preferences::GetCString("network.trr.uri", mUri);

    // Wait for captive portal?
    Preferences::GetBool("network.trr.wait-for-captive", &mWaitForCaptive);
    LOG(("Initialized TRRService\n"));
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
    LOG(("TRR::Observe() topic=%s\n", aTopic));
    if (!strcmp(aTopic, kCaptivePortalLoginSuccessEvent)) {
      // The user has successfully logged in. We have connectivity.
      fprintf(stderr, "-=*) TRRservice captive portal is okay (*=-\n");
    } else if (!strcmp(aTopic, kCaptivePortalLoginEvent)) {
      // The user is locked up behind a portal
      fprintf(stderr, "-=*) TRRservice captive portal is LOCKED (*=-\n");
    }
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
