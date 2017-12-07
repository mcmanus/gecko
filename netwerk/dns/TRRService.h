/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef TRRService_h_
#define TRRService_h_

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
{
public:
    NS_DECL_ISUPPORTS
    NS_DECL_NSIOBSERVER

    TRRService();
    nsresult Init();
    nsresult Start();
    nsresult Stop();
    bool Enabled();

    ResolverMode Mode() { return static_cast<ResolverMode>(mMode); }

private:
    virtual  ~TRRService();
    nsresult ReadPrefs(const char *name);
    void GetPrefBranch(nsIPrefBranch **result);
    bool      mStarted;
    bool      mInitialized;
    uint32_t mMode;
    nsCString mUri;
    bool      mWaitForCaptive;
    bool      mRfc1918;        // allow RFC1918 addresses ?
    bool      mCaptiveIsPassed;
};


nsresult
TRRServiceConstructor(nsISupports *aOuter, REFNSIID aIID, void **aResult);

extern TRRService *gTRRService;

} // namespace net
} // namespace mozilla

#endif // TRRService_h_
