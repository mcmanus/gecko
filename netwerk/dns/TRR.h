/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_TRR_h
#define mozilla_net_TRR_h

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

class DOHresp {
public:
  virtual ~DOHresp() { }
  nsresult Add(uint32_t TTL, nsCString & dns, int index, uint16_t len,
               bool aLocalAllowed);
  uint16_t mNumAddresses;
  LinkedList<DOHaddr> mAddresses;
};

class TRR
  : public Runnable
  , public nsIStreamListener
{
public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSIREQUESTOBSERVER
  NS_DECL_NSISTREAMLISTENER

  explicit TRR(nsHostResolver *aResolver,
               nsHostRecord *aRec,
               enum TrrType aType)
    : mozilla::Runnable("TRR")
    , mRec(aRec)
    , mHostResolver(aResolver)
    , mTRRService(gTRRService)
    , mType(aType)
  {
    mHost = aRec->host;
  }

  explicit TRR(nsHostResolver *aResolver,
               nsCString aHost,
               enum TrrType aType)
    : mozilla::Runnable("TRR")
    , mHost(aHost)
    , mRec(nullptr)
    , mHostResolver(aResolver)
    , mTRRService(gTRRService)
    , mType(aType)
  {
  }

  NS_IMETHOD Run() override;
  nsCString   mHost;
  nsHostRecord *mRec;
  RefPtr<nsHostResolver> mHostResolver;
  TRRService *mTRRService;

private:
  ~TRR() {}
  nsresult DNSoverHTTPS();
  nsresult DohDecode();
  nsresult ReturnData();
  nsresult FailData();

  enum TrrType mType;
  TimeStamp mStartTime;
  nsCString mResponse;
  DOHresp mDNS;
};

} // namespace net
} // namespace mozilla

#endif // include guard
