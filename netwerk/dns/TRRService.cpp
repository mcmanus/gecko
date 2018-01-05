/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
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
static const char kClearPrivateData[] = "clear-private-data";

#define TRR_PREF_PREFIX           "network.trr."
#define TRR_PREF(x)               TRR_PREF_PREFIX x

namespace mozilla {
namespace net {

extern LazyLogModule gHostResolverLog;
#undef LOG
#define LOG(args) MOZ_LOG(gHostResolverLog, mozilla::LogLevel::Debug, args)

TRRService *gTRRService = nullptr;

NS_IMPL_ISUPPORTS(TRRService, nsIObserver, nsISupportsWeakReference)

TRRService::TRRService()
  : mInitialized(false)
  , mMode(0)
  , mLock("trrservice")
  , mWaitForCaptive(true)
  , mRfc1918(false)
  , mCaptiveIsPassed(false)
  , mUseGET(false)
{
  MOZ_ASSERT(NS_IsMainThread(), "wrong thread");
}

nsresult
TRRService::Init()
{
  MOZ_ASSERT(NS_IsMainThread(), "wrong thread");
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
    observerService->AddObserver(this, kClearPrivateData, true);
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
  MOZ_ASSERT(NS_IsMainThread(), "wrong thread");
  *result = nullptr;
  CallGetService(NS_PREFSERVICE_CONTRACTID, result);
}

nsresult
TRRService::ReadPrefs(const char *name)
{
  MOZ_ASSERT(NS_IsMainThread(), "wrong thread");
  if (!name || !strcmp(name, TRR_PREF("mode"))) {
    // 0 - off, 1 - parallel, 2 TRR first, 3 TRR only
    uint32_t tmp;
    if (NS_SUCCEEDED(Preferences::GetUint(TRR_PREF("mode"), &tmp))) {
      mMode = tmp;
    }
  }
  if (!name || !strcmp(name, TRR_PREF("uri"))) {
    // Base URI, appends "?ct&body=..."
    Preferences::GetCString(TRR_PREF("uri"), mPrivateURI);
  }
  if (!name || !strcmp(name, TRR_PREF("credentials"))) {
    Preferences::GetCString(TRR_PREF("credentials"), mPrivateCred);
  }
  if (!name || !strcmp(name, TRR_PREF("wait-for-portal"))) {
    // Wait for captive portal?
    bool tmp;
    if (NS_SUCCEEDED(Preferences::GetBool(TRR_PREF("wait-for-portal"), &tmp))) {
      mWaitForCaptive = tmp;
    }
  }
  if (!name || !strcmp(name, TRR_PREF("allow-rfc1918"))) {
    bool tmp;
    if (NS_SUCCEEDED(Preferences::GetBool(TRR_PREF("allow-rfc1918"), &tmp))) {
      mRfc1918 = tmp;
    }
  }
  if (!name || !strcmp(name, TRR_PREF("useGET"))) {
    bool tmp;
    if (NS_SUCCEEDED(Preferences::GetBool(TRR_PREF("useGET"), &tmp))) {
      mUseGET = tmp;
    }
  }

  return NS_OK;
}

nsresult
TRRService::GetURI(nsCString &result)
{
  MutexAutoLock lock(mLock);
  result = mPrivateURI;
  return NS_OK;
}

nsresult
TRRService::GetCredentials(nsCString &result)
{
  MutexAutoLock lock(mLock);
  result = mPrivateCred;
  return NS_OK;
}

nsresult
TRRService::Start()
{
  MOZ_ASSERT(NS_IsMainThread(), "wrong thread");
  if (!mInitialized) {
    return NS_ERROR_NOT_INITIALIZED;
  }
  return NS_OK;
}

nsresult
TRRService::Stop()
{
  MOZ_ASSERT(NS_IsMainThread(), "wrong thread");
  return NS_OK;
}

TRRService::~TRRService()
{
  MOZ_ASSERT(NS_IsMainThread(), "wrong thread");
  LOG(("Exiting TRRService\n"));
  gTRRService = nullptr;
}

NS_IMETHODIMP
TRRService::Observe(nsISupports *aSubject,
                    const char * aTopic,
                    const char16_t * aData)
{
  MOZ_ASSERT(NS_IsMainThread(), "wrong thread");
  LOG(("TRR::Observe() topic=%s\n", aTopic));
  if (!strcmp(aTopic, NS_PREFBRANCH_PREFCHANGE_TOPIC_ID)) {
    ReadPrefs(NS_ConvertUTF16toUTF8(aData).get());
  } else if (!strcmp(aTopic, kOpenCaptivePortalLoginEvent)) {
    // We are in a captive portal
    fprintf(stderr,"TRRservice in captive portal\n");
    mCaptiveIsPassed = false;
  } else if (!strcmp(aTopic, NS_CAPTIVE_PORTAL_CONNECTIVITY)) {
    nsAutoCString data = NS_ConvertUTF16toUTF8(aData);
    fprintf(stderr, "-=*) TRRservice captive portal was %s (*=-\n",
            data.get());
    mCaptiveIsPassed = true;
  } else if (!strcmp(aTopic, kClearPrivateData)) {
    // flush the TRR blacklist, both in-memory and on-disk
  }
  return NS_OK;
}

#undef LOG

} // namespace net
} // namespace mozilla
