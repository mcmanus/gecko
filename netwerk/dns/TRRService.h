/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef TRRService_h_
#define TRRService_h_

#include "nsIObserver.h"

namespace mozilla {
namespace net {

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

private:
    virtual ~TRRService();
    bool     mStarted;
    bool     mInitialized;
};


nsresult
TRRServiceConstructor(nsISupports *aOuter, REFNSIID aIID, void **aResult);

} // namespace net
} // namespace mozilla

#endif // TRRService_h_
