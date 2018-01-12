/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nsICaptivePortalService.h"
#include "nsIObserverService.h"
#include "TRR.h"
#include "TRRService.h"

#include "mozilla/Preferences.h"

static const char kOpenCaptivePortalLoginEvent[] = "captive-portal-login";
static const char kClearPrivateData[] = "clear-private-data";
static const char kPurge[] = "browser:purge-session-history";

const static uint32_t kTRRBlacklistExpireTime = 3600*24*3; // three days

#define TRR_PREF_PREFIX           "network.trr."
#define TRR_PREF(x)               TRR_PREF_PREFIX x

namespace mozilla {
namespace net {

#undef LOG
extern mozilla::LazyLogModule gHostResolverLog;
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
  , mClearStorage(false)
  , mConfirmationState(0)
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

  nsCOMPtr<nsIObserverService> observerService =
    mozilla::services::GetObserverService();
  if (observerService) {
    observerService->AddObserver(this, NS_CAPTIVE_PORTAL_CONNECTIVITY, true);
    observerService->AddObserver(this, kOpenCaptivePortalLoginEvent, true);
    observerService->AddObserver(this, kClearPrivateData, true);
    observerService->AddObserver(this, kPurge, true);
  }
  nsCOMPtr<nsIPrefBranch> prefBranch;
  GetPrefBranch(getter_AddRefs(prefBranch));
  if (prefBranch) {
    prefBranch->AddObserver(TRR_PREF_PREFIX, this, true);
  }

  ReadPrefs(NULL);

  gTRRService = this;

  LOG(("Initialized TRRService\n"));
  return NS_OK;
}

bool
TRRService::Enabled()
{
  if (mConfirmationState != 2) {
    MaybeConfirm();
    return false;
  }

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
    nsCString old(mPrivateURI);
    Preferences::GetCString(TRR_PREF("uri"), mPrivateURI);
    if (old.Length() && !mPrivateURI.Equals(old)) {
      mClearStorage = true;
      LOG(("TRRService clearing blacklist because of change is uri service\n"));
    }
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
    LOG(("TRRservice in captive portal\n"));
    mCaptiveIsPassed = false;
  } else if (!strcmp(aTopic, NS_CAPTIVE_PORTAL_CONNECTIVITY)) {
    nsAutoCString data = NS_ConvertUTF16toUTF8(aData);
    LOG(("TRRservice captive portal was %s\n", data.get()));
    if (!mStorage) {
      mStorage = DataStorage::Get(DataStorageClass::TRRBlacklist);
      if (mStorage) {
        bool storageWillPersist = true;
        if (NS_FAILED(mStorage->Init(storageWillPersist))) {
          mStorage = nullptr;
        }
        if (mClearStorage) {
          mStorage->Clear();
          mClearStorage = false;
        }
      }
    }

    mConfirmationState = 1;
    MaybeConfirm();
    mCaptiveIsPassed = true;

  } else if (!strcmp(aTopic, kClearPrivateData) ||
             !strcmp(aTopic, kPurge)) {
    // flush the TRR blacklist, both in-memory and on-disk
    if (mStorage) {
      mStorage->Clear();
    }
  }
  return NS_OK;
}

void
TRRService::MaybeConfirm()
{
  if (mConfirmer || mConfirmationState != 1) {
    return;
  }
  mConfirmer = new TRR(this, NS_LITERAL_CSTRING("mozilla.org"),
                       TRRTYPE_NS, false);
  NS_DispatchToMainThread(mConfirmer);
}

bool
TRRService::IsTRRBlacklisted(const nsCString &aHost, bool privateBrowsing,
                             bool aParentsToo) // false if domain
{
  if (mClearStorage) {
    mStorage->Clear();
    mClearStorage = false;
  }

  // hardcode these so as to not worry about expiration
  if (StringEndsWith(aHost, NS_LITERAL_CSTRING(".local")) ||
      aHost.Equals(NS_LITERAL_CSTRING("localhost"))) {
    return true;
  }
    
  if (!Enabled()) {
    return true;
  }
  if (!mStorage) {
    return false;
  }

  int32_t dot = aHost.FindChar('.');
  if ((dot == kNotFound) && aParentsToo) {
    // Only if a full host name. Domains can be dotless to be able to
    // blacklist entire TLDs
    return true;
  } else if(dot != kNotFound) {
    // there was a dot, check the parent first
    dot++;
    nsDependentCSubstring domain = Substring(aHost, dot, aHost.Length() - dot);
    nsAutoCString check(domain);

    // recursively check the domain part of this name
    if (IsTRRBlacklisted(check, privateBrowsing, false)) {
      // the domain name of this name is already TRR blacklisted
      return true;
    }
  }

  MutexAutoLock lock(mLock);
  // use a unified casing for the hashkey
  nsAutoCString hashkey(aHost.get());
  nsCString val(mStorage->Get(hashkey, privateBrowsing ?
                              DataStorage_Private : DataStorage_Persistent));

  if (!val.IsEmpty()) {
    nsresult code;
    int32_t until = val.ToInteger(&code) + kTRRBlacklistExpireTime;
    int32_t expire = NowInSeconds();
    if (NS_SUCCEEDED(code) && (until > expire)) {
      LOG(("Host [%s] is TRR blacklisted\n", aHost.get()));
      return true;
    } else {
      // the blacklisted entry has expired
      mStorage->Remove(hashkey, privateBrowsing ?
                       DataStorage_Private : DataStorage_Persistent);
    }
  }
  return false;
}

class proxyBlacklist : public Runnable
{
public:
  proxyBlacklist(TRRService *service, const nsCString &aHost, bool pb, bool aParentsToo)
    : mozilla::Runnable("proxyBlackList")
    , mService(service), mHost(aHost), mPB(pb), mParentsToo(aParentsToo)
  { }

  NS_IMETHOD Run() override
  {
    mService->TRRBlacklist(mHost, mPB, mParentsToo);
    mService = nullptr;
    return NS_OK;
  }

private:
  RefPtr<TRRService> mService;
  nsCString mHost;
  bool      mPB;
  bool      mParentsToo;
};

void
TRRService::TRRBlacklist(const nsCString &aHost, bool privateBrowsing, bool aParentsToo)
{
  if (!mStorage) {
    return;
  }

  if (!NS_IsMainThread()) {
    NS_DispatchToMainThread(new proxyBlacklist(this, aHost,
                                               privateBrowsing, aParentsToo));
    return;
  }

  LOG(("TRR blacklist %s\n", aHost.get()));
  nsAutoCString hashkey(aHost.get());
  nsAutoCString val;
  val.AppendInt( NowInSeconds() ); // creation time

  // this overwrites any existing entry
  {
    MutexAutoLock lock(mLock);
    mStorage->Put(hashkey, val, privateBrowsing ?
                  DataStorage_Private : DataStorage_Persistent);
  }

  if (aParentsToo) {
    // when given a full host name, verify its domain as well
    int32_t dot = aHost.FindChar('.');
    if (dot != kNotFound) {
      // this has a domain to be checked
      dot++;
      nsDependentCSubstring domain = Substring(aHost, dot, aHost.Length() - dot);
      nsAutoCString check(domain);
      if (IsTRRBlacklisted(check, privateBrowsing, false)) {
        // the domain part is already blacklisted, no need to add this entry
        return;
      }
      // verify 'check' over TRR
      LOG(("TRR: verify if '%s' resolves as NS\n", check.get()));

      // check if there's an NS entry for this name
      RefPtr<TRR> trr = new TRR(this, check, TRRTYPE_NS, privateBrowsing);
      NS_DispatchToMainThread(trr);
    }
  }
}

AHostResolver::LookupStatus
TRRService::CompleteLookup(nsHostRecord *rec, nsresult status, AddrInfo *aNewRRSet, bool pb)
{
  // this is an NS check for the TRR blacklist

  MOZ_ASSERT(NS_IsMainThread());
  MOZ_ASSERT(!rec);

  nsAutoPtr<AddrInfo> newRRSet(aNewRRSet);
  MOZ_ASSERT(newRRSet && newRRSet->isTRR() == TRRTYPE_NS);

  if (!strcmp(newRRSet->mHostName, "mozilla.org")) {
    MOZ_ASSERT(mConfirmer);
    mConfirmationState = NS_SUCCEEDED(status) ? 2 : 3;
    mConfirmer = nullptr;
    return LOOKUP_OK;
  }

  // when called without a host record, this is a domain name check response.
  if (NS_SUCCEEDED(status)) {
    LOG(("TRR verified %s to be fine!\n", newRRSet->mHostName));
    // whitelist?
  } else {
    LOG(("TRR says %s doesn't resove as NS!\n", newRRSet->mHostName));
    TRRBlacklist(nsCString(newRRSet->mHostName), pb, false);
  }
  return LOOKUP_OK;
}

#undef LOG

} // namespace net
} // namespace mozilla
