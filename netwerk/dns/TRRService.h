/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef TRRService_h_
#define TRRService_h_

#include "mozilla/Atomics.h"
#include "nsCOMPtr.h"
#include "nsWeakReference.h"
#include "nsIPrefService.h"
#include "nsIObserver.h"

namespace mozilla {
namespace net {

enum ResolverMode {
  MODE_NATIVEONLY, // TRR OFF
  MODE_PARALLEL,   // use the first response
  MODE_TRRFIRST,   // fallback to native on TRR failure
  MODE_TRRONLY     // don't even fallback
};

class TRRService
  : public nsIObserver
  , public nsSupportsWeakReference
{
public:
  NS_DECL_ISUPPORTS
  NS_DECL_NSIOBSERVER

  TRRService();
  nsresult Init();
  nsresult Start();
  nsresult Stop();
  bool Enabled();

  uint32_t Mode() { return mMode; }
  bool AllowRFC1918() { return mRfc1918; }
  nsresult GetURI(nsCString &result);
  nsresult GetCredentials(nsCString &result);

private:
  virtual  ~TRRService();
  nsresult ReadPrefs(const char *name);
  void GetPrefBranch(nsIPrefBranch **result);
  Atomic<bool, Relaxed>     mInitialized;
  Atomic<uint32_t, Relaxed> mMode;

  Mutex mLock; // protects mPrivate* string
  nsCString mPrivateURI; // main thread only
  nsCString mPrivateCred; // main thread only

  Atomic<bool, Relaxed> mWaitForCaptive;
  Atomic<bool, Relaxed> mRfc1918;
  Atomic<bool, Relaxed> mCaptiveIsPassed;
};

extern TRRService *gTRRService;

} // namespace net
} // namespace mozilla

#endif // TRRService_h_
