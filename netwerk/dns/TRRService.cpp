/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/net/TRRService.h"
#include "mozilla/Services.h"
#include "mozilla/Preferences.h"
#include "nsIObserverService.h"
#include "nsServiceManagerUtils.h"
#include "nsICaptivePortalService.h"

static const char kOpenCaptivePortalLoginEvent[] = "captive-portal-login";

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
        observerService->AddObserver(this, NS_CAPTIVE_PORTAL_CONNECTIVITY, true);
        observerService->AddObserver(this, kOpenCaptivePortalLoginEvent, true);
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

bool
TRRService::Enabled()
{
    return (!mWaitForCaptive || mCaptiveIsPassed);
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
    if (!name || !strcmp(name, TRR_PREF("credentials"))) {
        Preferences::GetCString(TRR_PREF("credentials"), mCred);
    }
    if (!name || !strcmp(name, TRR_PREF("wait-for-portal"))) {
        // Wait for captive portal?
        Preferences::GetBool(TRR_PREF("wait-for-portal"), &mWaitForCaptive);
    }
    if (!name || !strcmp(name, TRR_PREF("allow-rfc1918"))) {
        Preferences::GetBool(TRR_PREF("allow-rfc1918"), mRfc1918);
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
    else if (!strcmp(aTopic, kOpenCaptivePortalLoginEvent)) {
        // We are in a captive portal
        mCaptiveIsPassed = false;
    }
    else if (!strcmp(aTopic, NS_CAPTIVE_PORTAL_CONNECTIVITY)) {
        nsAutoCString data = NS_ConvertUTF16toUTF8(aData);
        fprintf(stderr, "-=*) TRRservice captive portal was %s (*=-\n",
                data.get());
        mCaptiveIsPassed = true;
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
