/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_TRR_h
#define mozilla_net_TRR_h

#include "nsIChannel.h"
#include "nsIHttpPushListener.h"
#include "nsIInterfaceRequestor.h"
#include "nsIStreamListener.h"

namespace mozilla { namespace net {

// the values map to RFC1035 type identifiers
enum TrrType {
  TRRTYPE_A = 1,
  TRRTYPE_NS = 2,
  TRRTYPE_CNAME = 5,
  TRRTYPE_AAAA = 28,
};

class DOHaddr : public LinkedListElement<DOHaddr> {
public:
  NetAddr mNet;
  uint32_t mTtl;
};

class TRRService;
extern TRRService *gTRRService;

class DOHresp {
public:
  virtual ~DOHresp() { }
  nsresult Add(uint32_t TTL, unsigned char *dns, int index, uint16_t len,
               bool aLocalAllowed);
  uint16_t mNumAddresses;
  LinkedList<DOHaddr> mAddresses;
};

class TRR
  : public Runnable
  , public nsIHttpPushListener
  , public nsIInterfaceRequestor
//  , public nsIRequestObserver from nsIStreamListener
  , public nsIStreamListener
{
public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSIHTTPPUSHLISTENER
  NS_DECL_NSIINTERFACEREQUESTOR
  NS_DECL_NSIREQUESTOBSERVER
  NS_DECL_NSISTREAMLISTENER

  static const unsigned int kMaxSize = 3200;
  explicit TRR(AHostResolver *aResolver,
               nsHostRecord *aRec,
               enum TrrType aType)
    : mozilla::Runnable("TRR")
    , mRec(aRec)
    , mHostResolver(aResolver)
    , mTRRService(gTRRService)
    , mType(aType)
    , mUsed(0)
    , mFailed(false)
  {
    mHost = aRec->host;
    mPB = aRec->pb;
  }

  explicit TRR(nsIHttpChannel *pushedChannel,
               AHostResolver *aResolver,
               bool aPB, nsHostRecord *pushedRec);

  explicit TRR(AHostResolver *aResolver,
               nsCString aHost,
               enum TrrType aType,
               bool aPB)
    : mozilla::Runnable("TRR")
    , mHost(aHost)
    , mHostResolver(aResolver)
    , mTRRService(gTRRService)
    , mType(aType)
    , mUsed(0)
    , mFailed(false)
    , mPB(aPB)
  { }

  NS_IMETHOD Run() override;
  void Cancel();
  enum TrrType Type() {return mType;}
  nsCString   mHost;
  RefPtr<nsHostRecord>   mRec;
  RefPtr<AHostResolver> mHostResolver;
  TRRService *mTRRService;

private:
  ~TRR() {}
  nsresult DNSoverHTTPS();
  nsresult DohEncode(nsCString &target);
  nsresult DohDecode();
  nsresult ReturnData();
  nsresult FailData();

  nsresult DohDecodeQuery(const nsCString &query,
                          nsCString &host, enum TrrType &type);
    
  nsCOMPtr<nsIChannel> mChannel;
  enum TrrType mType;
  TimeStamp mStartTime;
  unsigned char mResponse[kMaxSize];
  unsigned int mUsed;
  bool mFailed;
  bool mPB;
  DOHresp mDNS;
};

} // namespace net
} // namespace mozilla

#endif // include guard
