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

#define TRR_PREF_PREFIX           "network.trr."
#define TRR_PREF(x)               TRR_PREF_PREFIX x

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
    nsCOMPtr<nsIPrefBranch> prefBranch;
    GetPrefBranch(getter_AddRefs(prefBranch));
    if (prefBranch) {
        prefBranch->AddObserver(TRR_PREF_PREFIX, this, true);
    }

    ReadPrefs(NULL);

    LOG(("Initialized TRRService\n"));
    return NS_OK;
}

void
TRRService::GetPrefBranch(nsIPrefBranch **result)
{
    *result = nullptr;
    CallGetService(NS_PREFSERVICE_CONTRACTID, result);
}

nsresult
TRRService::ReadPrefs(const char *name)
{
    if (!name || !strcmp(name, TRR_PREF("mode"))) {
        // 0 - off, 1 - parallel, 2 TRR first, 3 TRR only
        Preferences::GetUint(TRR_PREF("mode"), &mMode);
    }
    if (!name || !strcmp(name, TRR_PREF("uri"))) {
        // Base URI, appends "?body=..."
        Preferences::GetCString(TRR_PREF("uri"), mUri);
    }
    if (!name || !strcmp(name, TRR_PREF("wait-for-portal"))) {
        // Wait for captive portal?
        Preferences::GetBool(TRR_PREF("wait-for-portal"), &mWaitForCaptive);
    }

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
    if (!strcmp(aTopic, NS_PREFBRANCH_PREFCHANGE_TOPIC_ID)) {
        ReadPrefs(NS_ConvertUTF16toUTF8(aData).get());
    }
    else if (!strcmp(aTopic, kCaptivePortalLoginSuccessEvent)) {
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
