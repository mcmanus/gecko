/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_TRR_h
#define mozilla_net_TRR_h

#include "nsIStreamListener.h"

namespace mozilla { namespace net {

class TRR: public Runnable
{
public:
    explicit TRR(nsHostResolver *aResolver,
                 nsHostRecord *aRec,
                 bool aIPv6)
      : mozilla::Runnable("TRR")
      , mRec(aRec)
      , mHostResolver(aResolver)
    {
        mHostname = aRec->host;
        mAf = aIPv6 ? AF_INET6 : AF_INET;
        mResolverThread = NS_GetCurrentThread();
    }

    NS_IMETHOD Run() override
    {
        MOZ_ASSERT(NS_IsMainThread());
#if 0
        nsCOMPtr<nsIObserverService> obs = services::GetObserverService();
        if (obs) {
            obs->NotifyObservers(nullptr,
                                 "trr-resolution-request",
                                 NS_ConvertUTF8toUTF16(mHostname).get());
        }
#endif
        // Name resolve asynchronously by sending a GET over HTTPS using HTTP/2
        fprintf(stderr, "TRRRRRRRRRRRRRRRRRRrr\n");

        DNSoverHTTPS();
        return NS_OK;
    }
    nsCOMPtr<nsIEventTarget> GetResolverThread() { return mResolverThread; }
    nsCString   mHostname;
    nsHostRecord *mRec;
    nsHostResolver *mHostResolver;

private:
    uint16_t    mAf;
    nsCOMPtr<nsIEventTarget> mResolverThread;
    nsresult DNSoverHTTPS();
};


class DOHaddr : public LinkedListElement<DOHaddr> {
public:
    NetAddr mNet;
    uint32_t mTtl;
};

class DOHresp {
public:
    virtual ~DOHresp() {

    }
    nsresult Add(uint32_t TTL, nsCString & dns, int index, uint16_t len,
                 nsAutoCString & host);
    uint16_t mNumAddresses;
    LinkedList<DOHaddr> mAddresses;
private:
    int mIndex; // which entry to write
};

class DOHListener : public nsIStreamListener
{
public:
    NS_DECL_ISUPPORTS
    NS_DECL_NSIREQUESTOBSERVER
    NS_DECL_NSISTREAMLISTENER

    DOHListener(TRR *aTrr)
      : mTrr(aTrr)
    { }

private:
    virtual ~DOHListener() { }
    RefPtr<TRR> mTrr;
    TimeStamp mStartTime;
    nsCString mResponse;
    nsresult dohDecode();
    nsresult returnData();
    DOHresp mDNS;
};


} // namespace net
} // namespace mozilla

#endif // include guard
