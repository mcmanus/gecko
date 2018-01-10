/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=4 sw=4 sts=4 et cin: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "DNS.h"
#include "nsContentUtils.h"
#include "nsHostResolver.h"
#include "nsIHttpChannel.h"
#include "nsIHttpChannelInternal.h"
#include "nsIInputStream.h"
#include "nsIIOService.h"
#include "nsISupportsBase.h"
#include "nsISupportsUtils.h"
#include "nsIUploadChannel2.h"
#include "nsNetUtil.h"
#include "nsThreadUtils.h"
#include "nsStringStream.h"
#include "nsURLHelper.h"
#include "TRR.h"
#include "TRRService.h"

#include "mozilla/Base64.h"
#include "mozilla/DebugOnly.h"
#include "mozilla/Logging.h"
#include "mozilla/Preferences.h"
#include "mozilla/Telemetry.h"
#include "mozilla/TimeStamp.h"

#undef LOG
#define LOG(...) fprintf(stderr, __VA_ARGS__)

namespace mozilla {
namespace net {

NS_IMPL_ISUPPORTS(TRR,
                  nsIStreamListener,
                  nsIRequestObserver)

// convert a given host request to a DOH 'body'
//
nsresult
TRR::DohEncode(nsCString &aBody)
{
  const uint8_t DNS_CLASS_IN = 1;

  aBody.Truncate();
  // Header
  aBody += '\0';
  aBody += '\0'; // 16 bit id
  aBody += '\0'; // |QR|   Opcode  |AA|TC|RD|
  aBody += '\0'; // |RA|   Z    |   RCODE   |
  aBody += '\0';
  aBody += 1;    // QDCOUNT (number of entries in the question section)
  aBody += '\0';
  aBody += '\0'; // ANCOUNT
  aBody += '\0';
  aBody += '\0'; // NSCOUNT
  aBody += '\0';
  aBody += '\0'; // ARCOUNT

  // Question

  // The input host name should be converted to a sequence of labels, where
  // each label consists of a length octet followed by that number of
  // octets.  The domain name terminates with the zero length octet for the
  // null label of the root.
  // Followed by 16 bit QTYPE and 16 bit QCLASS

  PRInt32 index = 0;
  PRInt32 offset = 0;
  do {
    bool dotFound = false;
    PRInt32 labelLength;
    index = mHost.FindChar('.', offset);
    if (kNotFound != index) {
      dotFound = true;
      labelLength = index - offset;
    } else {
      labelLength = mHost.Length() - offset;
    }
    if (labelLength > 63) {
      // too long label!
      return NS_ERROR_UNEXPECTED;
    }
    aBody += static_cast<unsigned char>(labelLength);
    nsDependentCSubstring label = Substring(mHost, offset, labelLength);
    aBody.Append(label);
    if(!dotFound) {
      aBody += '\0'; // terminate with a final zero
      break;
    }
    offset += labelLength + 1; // move over label and dot
  } while(1);

  aBody += '\0'; // upper 8 bit TYPE
  aBody += static_cast<uint8_t>(mType);
  aBody += '\0'; // upper 8 bit CLASS
  aBody += DNS_CLASS_IN;    // IN - "the Internet"

  return NS_OK;
}

NS_IMETHODIMP
TRR::Run()
{
  MOZ_ASSERT(NS_IsMainThread());
  MOZ_ASSERT(mTRRService);
  if (NS_FAILED(DNSoverHTTPS())) {
    FailData();
    // The dtor will now be run
  }
  return NS_OK;
}

nsresult
TRR::DNSoverHTTPS()
{
  // This is essentially the "run" method - created from nsHostResolver
  MOZ_ASSERT(NS_IsMainThread(), "wrong thread");

  if ((mType != TRRTYPE_A) && (mType != TRRTYPE_AAAA) && (mType != TRRTYPE_NS)) {
    // limit the calling interface becase nsHostResolver has explicit slots for
    // these types
    return NS_ERROR_FAILURE;
  }
  
  // 'host' should be converted to a DNS query packet for QTYPE "A" or
  // "AAAA" (based on af), then base64url-encoded and inserted into the URL
  //
  nsresult rv;
  nsCOMPtr<nsIIOService> ios(do_GetIOService(&rv));
  NS_ENSURE_SUCCESS(rv, rv);

  // body=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB

  // the raw example 'body':
  // 00000000  ab cd 01 00 00 01 00 00  00 00 00 00 03 77 77 77  |.............www|
  // 00000010  07 65 78 61 6d 70 6c 65  03 63 6f 6d 00 00 01 00  |.example.com....|
  // 00000020  01                                                |.|

  bool useGet = mTRRService->UseGET();
  nsAutoCString body;
  nsCOMPtr<nsIURI> dnsURI;

  if (useGet) {
    nsAutoCString tmp;
    rv = DohEncode(tmp);
    NS_ENSURE_SUCCESS(rv, rv);

    rv = Base64URLEncode(tmp.Length(), reinterpret_cast<const unsigned char *>(tmp.get()),
                         Base64URLEncodePaddingPolicy::Omit, body);
    NS_ENSURE_SUCCESS(rv, rv);

    nsCString uri;
    mTRRService->GetURI(uri);
    uri.Append(NS_LITERAL_CSTRING("?ct=application/udp-wireformat&body="));
    uri.Append(body);
    NS_NewURI(getter_AddRefs(dnsURI), uri);
  } else {
    rv = DohEncode(body);
    NS_ENSURE_SUCCESS(rv, rv);

    nsCString uri;
    mTRRService->GetURI(uri);
    NS_NewURI(getter_AddRefs(dnsURI), uri);
  }

  NS_NewChannel(getter_AddRefs(mChannel),
                dnsURI,
                nsContentUtils::GetSystemPrincipal(),
                nsILoadInfo::SEC_ALLOW_CROSS_ORIGIN_DATA_IS_NULL,
                nsIContentPolicy::TYPE_OTHER,
                nullptr, // aLoadGroup
                nullptr, // aCallbacks
                nsIRequest::LOAD_ANONYMOUS, ios);

  nsCOMPtr<nsIHttpChannel> httpChannel = do_QueryInterface(mChannel);
  if (!httpChannel) {
    return NS_ERROR_UNEXPECTED;
  }

  rv = httpChannel->SetRequestHeader(NS_LITERAL_CSTRING("Accept"),
                                     NS_LITERAL_CSTRING("application/dns-udpwireformat"),
                                     false);
  NS_ENSURE_SUCCESS(rv, rv);

  nsCString cred;
  mTRRService->GetCredentials(cred);
  if (cred.Length()){
    rv = httpChannel->SetRequestHeader(NS_LITERAL_CSTRING("Authorization"), cred, false);
    NS_ENSURE_SUCCESS(rv, rv);
  }

  nsCOMPtr<nsIHttpChannelInternal> internalChannel = do_QueryInterface(mChannel);
  if (!internalChannel) {
    return NS_ERROR_UNEXPECTED;
  }

  // setting a small stream window means the h2 stack won't pipeline a window update
  // with each HEADERS
  rv = internalChannel->SetInitialRwin(kMaxSize + 1024);
  NS_ENSURE_SUCCESS(rv, rv);
  rv = internalChannel->SetTrr(true);
  NS_ENSURE_SUCCESS(rv, rv);

  if (useGet) {
    rv = httpChannel->SetRequestMethod(NS_LITERAL_CSTRING("GET"));
    NS_ENSURE_SUCCESS(rv, rv);
  } else {
    rv = httpChannel->SetRequestHeader(NS_LITERAL_CSTRING("Cache-Control"),
                                       NS_LITERAL_CSTRING("no-store"), false);
    NS_ENSURE_SUCCESS(rv, rv);
    nsCOMPtr<nsIUploadChannel2> uploadChannel = do_QueryInterface(httpChannel);
    if (!uploadChannel) {
      return NS_ERROR_UNEXPECTED;
    }
    nsCOMPtr<nsIInputStream> uploadStream;
    rv = NS_NewCStringInputStream(getter_AddRefs(uploadStream), body);
    NS_ENSURE_SUCCESS(rv, rv);

    rv = uploadChannel->ExplicitSetUploadStream(uploadStream,
                                                NS_LITERAL_CSTRING("application/dns-udpwireformat"),
                                                body.Length(),
                                                NS_LITERAL_CSTRING("POST"), false);
    NS_ENSURE_SUCCESS(rv, rv);
  }

  if (NS_SUCCEEDED(httpChannel->AsyncOpen2(this))) {
    return NS_OK;
  }
  mChannel = nullptr;
  return NS_ERROR_UNEXPECTED;
}

NS_IMETHODIMP
TRR::OnStartRequest(nsIRequest *aRequest,
                    nsISupports *aContext)
{
  mStartTime = TimeStamp::Now();
  return NS_OK;
}

static uint16_t get16bit(unsigned char *aData, int index)
{
  return (static_cast<uint8_t>(aData[index]) << 8) |
    static_cast<uint8_t>(aData[index + 1]);
}

static uint32_t get32bit(unsigned char *aData, int index)
{
  return (static_cast<uint8_t>(aData[index]) << 24) |
    (static_cast<uint8_t>(aData[index+1])<<16) |
    (static_cast<uint8_t>(aData[index+2]) << 8) |
    static_cast<uint8_t>(aData[index+3]);
}
//
// DohDecode() collects the TTL and the IP addresses in the response
//
nsresult
TRR::DohDecode()
{
  // The response has a 12 byte header followed by the question (returned)
  // and then the answer. The answer section itself contains the name, type
  // and class again and THEN the record data.

  // www.example.com response:
  // header:
  // abcd 8180 0001 0001 0000 0000
  // the question:
  // 0377 7777 0765 7861 6d70 6c65 0363 6f6d 0000 0100 01
  // the answer:
  // 03 7777 7707 6578 616d 706c 6503 636f 6d00 0001 0001
  // 0000 0080 0004 5db8 d822

  unsigned int index = 12;
  uint8_t length;
  nsAutoCString host;

  LOG("doh decode %s %d bytes\n", mHost.get(), mUsed);

  if (mUsed < 12 || mResponse[0] || mResponse[1]) {
    LOG("TRR bad incoming DOH, eject!\n");
    return NS_ERROR_UNEXPECTED;
  }

  uint16_t questionRecords = get16bit(mResponse, 4); // qdcount
  // iterate over the single(?) host name in question
  while (questionRecords) {
    do {
      if (mUsed < (index + 1)) {
        return NS_ERROR_UNEXPECTED;
      }
      length = static_cast<uint8_t>(mResponse[index]);
      if (length) {
        if (host.Length()) {
          host.Append(".");
        }
        if (mUsed < (index + 1 + length)) {
          return NS_ERROR_UNEXPECTED;
        }
        host.Append(((char *)mResponse) + index + 1, length);
      }
      index += 1 + length; // skip length byte + label
    } while (length);
    if (mUsed < (index + 4)) {
      return NS_ERROR_UNEXPECTED;
    }
    index += 4; // skip question's type, class
    questionRecords--;
  }
  
  fprintf(stderr,"TRR Decode: index %u of %u\n",
          index, mUsed);

  // Figure out the number of answer records from ANCOUNT
  uint16_t answerRecords = get16bit(mResponse, 6);

  LOG("TRR Decode: %d answer records (%u bytes body) %s\n",
      answerRecords, mUsed, host.get());

  while (answerRecords) {

    if (mUsed < (index + 1)) {
      return NS_ERROR_UNEXPECTED;
    }
    length = static_cast<uint8_t>(mResponse[index]);
    if ((length & 0xc0) == 0xc0) {
      // name pointer, advance over it
      if (mUsed < (index + 2)) {
        return NS_ERROR_UNEXPECTED;
      }
      index += 2;
    } else if (length & 0xc0) {
      // illegal length, bail out
      LOG("TRR: illegal label length byte (%x)\n", length);
      return NS_ERROR_UNEXPECTED;
    } else {
      // iterate over host name in answer
      do {
        if (mUsed < (index + 1)) {
          return NS_ERROR_UNEXPECTED;
        }
        length = static_cast<uint8_t>(mResponse[index]);
        if (mUsed < (index + 1 + length)) {
          return NS_ERROR_UNEXPECTED;
        }
        index += 1 + length;
        LOG("TRR: move over %d bytes\n", 1 + length);
      } while (length);
    }
    // 16 bit TYPE
    if (mUsed < (index + 2)) {
      return NS_ERROR_UNEXPECTED;
    }
    uint16_t TYPE = get16bit(mResponse, index);
    index += 2;

    // 16 bit class
    if (mUsed < (index + 2)) {
      return NS_ERROR_UNEXPECTED;
    }
    uint16_t CLASS = get16bit(mResponse, index);
    if (1 != CLASS) {
      LOG("TRR bad CLASS (%u)\n", CLASS);
      return NS_ERROR_UNEXPECTED;
    }
    index += 2;

    // 32 bit TTL (seconds)
    if (mUsed < (index + 4)) {
      return NS_ERROR_UNEXPECTED;
    }
    uint32_t TTL = get32bit(mResponse, index);
    index += 4;

    // 16 bit RDLENGTH
    if (mUsed < (index + 2)) {
      return NS_ERROR_UNEXPECTED;
    }
    uint16_t RDLENGTH = get16bit(mResponse, index);
    index += 2;

    if (mUsed < (index + RDLENGTH)) {
      return NS_ERROR_UNEXPECTED;
    }

    // RDATA
    // - A (TYPE 1):  4 bytes
    // - AAAA (TYPE 28): 16 bytes
    // - NS (TYPE 2): N bytes

    nsresult rv;
    switch(TYPE) {
    case TRRTYPE_A:
      if (RDLENGTH != 4) {
        LOG("TRR bad length for A (%u)\n", RDLENGTH);
        return NS_ERROR_UNEXPECTED;
      }
      rv = mDNS.Add(TTL, mResponse, index, RDLENGTH,
                    mTRRService->AllowRFC1918());
      if (NS_FAILED(rv)) {
        LOG("TRR got local IPv4 address!\n");
        return rv;
      }
      break;
    case TRRTYPE_AAAA:
      if (RDLENGTH != 16) {
        LOG("TRR bad length for AAAA (%u)\n", RDLENGTH);
        return NS_ERROR_UNEXPECTED;
      }
      rv = mDNS.Add(TTL, mResponse, index, RDLENGTH,
                    mTRRService->AllowRFC1918());
      if (NS_FAILED(rv)) {
        LOG("TRR got unique/local IPv6 address!\n");
        return rv;
      }
      break;

    case TRRTYPE_NS:
      break;
    case TRRTYPE_CNAME:
      break;

    default:
      // skip unknown record types
      LOG("TRR unsupported TYPE (%u) RDLENGTH %u\n", TYPE, RDLENGTH);
      break;
    }

    index += RDLENGTH;
    LOG("done with record type %u len %u index now %u of %u\n",
        TYPE, RDLENGTH, index, mUsed);
    answerRecords--;
  }

  // NSCOUNT
  uint16_t nsRecords = get16bit(mResponse, 8);
  LOG("TRR Decode: %d ns records (%u bytes body)\n", nsRecords,
      mUsed);
  while (nsRecords) {
    if (mUsed < (index + 1)) {
      return NS_ERROR_UNEXPECTED;
    }
    length = static_cast<uint8_t>(mResponse[index]);
    if ((length & 0xc0) == 0xc0) {
      // name pointer, advance over it
      if (mUsed < (index + 2)) {
        return NS_ERROR_UNEXPECTED;
      }
      index += 2;
    } else if (length & 0xc0) {
      // illegal length, bail out
      LOG("TRR: illegal label length byte (%x)\n", length);
      return NS_ERROR_UNEXPECTED;
    } else {
      // iterate over host name in answer
      do {
        if (mUsed < (index + 1)) {
          return NS_ERROR_UNEXPECTED;
        }
        length = static_cast<uint8_t>(mResponse[index]);
        if (mUsed < (index + 1 + length)) {
          return NS_ERROR_UNEXPECTED;
        }
        index += 1 + length;
        LOG("TRR: move over %d bytes\n", 1 + length);
      } while (length);
    }

    if (mUsed < (index + 8)) {
      return NS_ERROR_UNEXPECTED;
    }
    index += 2; // type
    index += 2; // class
    index += 4; // ttl

    // 16 bit RDLENGTH
    if (mUsed < (index + 2)) {
      return NS_ERROR_UNEXPECTED;
    }
    uint16_t RDLENGTH = get16bit(mResponse, index);
    index += 2;
    if (mUsed < (index + RDLENGTH)) {
      return NS_ERROR_UNEXPECTED;
    }
    index += RDLENGTH;
    LOG("done with nsRecord now %u of %u\n", index, mUsed);
    nsRecords--;
  }

  // additional resource records
  uint16_t arRecords = get16bit(mResponse, 10);
  LOG("TRR Decode: %d additional resource records (%u bytes body)\n",
      arRecords, mUsed);
  while (arRecords) {
    if (mUsed < (index + 1)) {
      return NS_ERROR_UNEXPECTED;
    }
    length = static_cast<uint8_t>(mResponse[index]);
    if ((length & 0xc0) == 0xc0) {
      // name pointer, advance over it
      if (mUsed < (index + 2)) {
        return NS_ERROR_UNEXPECTED;
      }
      index += 2;
    } else if (length & 0xc0) {
      // illegal length, bail out
      LOG("TRR: illegal label length byte (%x)\n", length);
      return NS_ERROR_UNEXPECTED;
    } else {
      // iterate over host name in answer
      do {
        if (mUsed < (index + 1)) {
          return NS_ERROR_UNEXPECTED;
        }
        length = static_cast<uint8_t>(mResponse[index]);
        if (mUsed < (index + 1 + length)) {
          return NS_ERROR_UNEXPECTED;
        }
        index += 1 + length;
        LOG("TRR: move over %d bytes\n", 1 + length);
      } while (length);
    }

    if (mUsed < (index + 8)) {
      return NS_ERROR_UNEXPECTED;
    }
    index += 2; // type
    index += 2; // class
    index += 4; // ttl

    // 16 bit RDLENGTH
    if (mUsed < (index + 2)) {
      return NS_ERROR_UNEXPECTED;
    }
    uint16_t RDLENGTH = get16bit(mResponse, index);
    index += 2;
    if (mUsed < (index + RDLENGTH)) {
      return NS_ERROR_UNEXPECTED;
    }
    index += RDLENGTH;
    LOG("done with additional rr now %u of %u\n", index, mUsed);
    arRecords--;
  }
  
  if (index != mUsed) {
    LOG("TRRRRRR: bad DNS parser (%u != %d)!\n", index, (int)mUsed);
    // failed to parse 100%, do not continue
    return NS_ERROR_UNEXPECTED;
  }

  if (mDNS.mAddresses.getFirst() == nullptr) {
    // no entries were stored!
    return NS_ERROR_FAILURE;
  }
  return NS_OK;
}

nsresult
TRR::ReturnData()
{
  // create and populate an AddrInfo instance to pass on
  AddrInfo *ai = new AddrInfo(mHost.get(), mType);
  DOHaddr *item;
  uint32_t ttl = AddrInfo::NO_TTL_DATA;
  while ((item = static_cast<DOHaddr*>(mDNS.mAddresses.popFirst()))) {
    PRNetAddr prAddr;
    NetAddrToPRNetAddr(&item->mNet, &prAddr);
    auto *addrElement = new NetAddrElement(&prAddr);
    ai->AddAddress(addrElement);
    if (item->mTtl < ttl) {
      // While the DNS packet might return individual TTLs for each address,
      // we can only return one value in the AddrInfo class so pick the
      // lowest number.
      ttl = item->mTtl;
    }
  }
  ai->ttl = ttl;
  if (!mHostResolver) {
    return NS_ERROR_FAILURE;
  }
  (void)mHostResolver->CompleteLookup(mRec, NS_OK, ai);
  mHostResolver = nullptr;
  mRec = nullptr;
  return NS_OK;
}

nsresult
TRR::FailData()
{
  if (!mHostResolver) {
    return NS_ERROR_FAILURE;
  }
  // create and populate an TRR AddrInfo instance to pass on to signal that
  // this comes from TRR
  AddrInfo *ai = new AddrInfo(mHost.get(), mType);

  (void)mHostResolver->CompleteLookup(mRec, NS_ERROR_FAILURE, ai);
  mHostResolver = nullptr;
  mRec = nullptr;
  return NS_OK;
}

NS_IMETHODIMP
TRR::OnStopRequest(nsIRequest *aRequest,
                   nsISupports *aContext,
                   nsresult aStatusCode)
{
  // The dtor will be run after the function returns
  LOG("TRR:OnStopRequest %s %d failed=%d code=%X\n",
      mHost.get(), mType, mFailed, aStatusCode);
  nsCOMPtr<nsIChannel> channel;
  channel.swap(mChannel);

  // if status was "fine", parse the response and pass on the answer
  if (!mFailed && NS_SUCCEEDED(aStatusCode)) {
    nsCOMPtr<nsIHttpChannel> httpChannel = do_QueryInterface(aRequest);
    if (!httpChannel) {
      return NS_ERROR_UNEXPECTED;
    }
    nsresult rv = NS_OK;
    uint32_t httpStatus;
    rv = httpChannel->GetResponseStatus(&httpStatus);
    if (NS_SUCCEEDED(rv) && httpStatus == 200) {
      // decode body and create an AddrInfo struct for the response
      rv = DohDecode();

      if (NS_SUCCEEDED(rv)) {
        // pass back the response data
        ReturnData();
        return NS_OK;
      }
    }
  }

  FailData();
  return NS_OK;
}

NS_IMETHODIMP
TRR::OnDataAvailable(nsIRequest *aRequest,
                     nsISupports *aContext,
                     nsIInputStream *aInputStream,
                     uint64_t aOffset,
                     const uint32_t aCount)
{
  // receive DNS response into the local buffer

  if (aCount + mUsed > kMaxSize) {
    mFailed = true;
    return NS_ERROR_FAILURE;
  }

  uint32_t count;
  nsresult rv = aInputStream->Read((char *)mResponse + mUsed, aCount, &count);
  if (NS_FAILED(rv)) {
    mFailed = true;
    return rv;
  }
  MOZ_ASSERT(count == aCount);
  mUsed += aCount;
  return NS_OK;
}

nsresult
DOHresp::Add(uint32_t TTL, unsigned char *dns, int index, uint16_t len,
             bool aLocalAllowed)
{
  DOHaddr *doh = new DOHaddr;
  NetAddr *addr = &doh->mNet;
  if (4 == len) {
    // IPv4
    addr->inet.family = AF_INET;
    addr->inet.port = 0; // unknown
    addr->inet.ip = ntohl(get32bit(dns, index));
  } else if (16 == len) {
    // IPv6
    addr->inet6.family = AF_INET6;
    addr->inet6.port = 0;     // unknown
    addr->inet6.flowinfo = 0; // unknown
    addr->inet6.scope_id = 0; // unknown
    for(int i = 0; i < 16; i++, index++) {
      addr->inet6.ip.u8[i] = dns[index];
    }
  } else {
    return NS_ERROR_UNEXPECTED;
  }

  if (IsIPAddrLocal(addr) && !aLocalAllowed) {
    return NS_ERROR_FAILURE;
  }
  doh->mTtl = TTL;
  mAddresses.insertBack(doh);

  return NS_OK;
}

class proxyCancel : public Runnable
{
public:
  proxyCancel(TRR *aTRR)
    : Runnable("proxyTrrCancel")
    , mTRR(aTRR)
  { }

  NS_IMETHOD Run() override
  {
    mTRR->Cancel();
    mTRR = nullptr;
    return NS_OK;
  }
    
private:
  RefPtr<TRR> mTRR;
};

void
TRR::Cancel()
{
  if (!NS_IsMainThread()) {
    NS_DispatchToMainThread(new proxyCancel(this));
    return;
  }
  if (mChannel) {
    LOG("TRR: %p canceling Channel %p %s %d\n", this,
        mChannel.get(), mHost.get(), mType);
    mChannel->Cancel(NS_ERROR_ABORT);
  }
}
    
// namespace
}
}
