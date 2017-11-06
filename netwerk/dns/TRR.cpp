/* vim:set ts=4 sw=4 sts=4 et cin: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <ctime>
#include "LoadInfo.h"
#include "nsError.h"
#include "nsISupportsBase.h"
#include "nsISupportsUtils.h"
#include "nsAutoPtr.h"
#include "nsPrintfCString.h"
#include "prthread.h"
#include "prerror.h"
#include "prtime.h"
#include "mozilla/Logging.h"
#include "PLDHashTable.h"
#include "plstr.h"
#include "nsURLHelper.h"
#include "nsThreadUtils.h"
#include "GeckoProfiler.h"
#include "nsHostResolver.h"
#include "TRR.h"
#include "nsContentUtils.h"
#include "nsIHttpChannel.h"
#include "nsIIOService.h"
#include "nsNetUtil.h"
#include "nsIInputStream.h"
#include "DNS.h"

#include "mozilla/HashFunctions.h"
#include "mozilla/Base64.h"
#include "mozilla/TimeStamp.h"
#include "mozilla/Telemetry.h"
#include "mozilla/DebugOnly.h"
#include "mozilla/Preferences.h"
#include "mozilla/LinkedList.h"

#undef LOG
#define LOG(...) fprintf(stderr, __VA_ARGS__)

using namespace mozilla;
using namespace mozilla::net;

NS_IMPL_ISUPPORTS(DOHListener,
                  nsIStreamListener,
                  nsIRequestObserver)

// convert a given host request to a DOH 'body'
//
// TODO: make it able to ask for both A and AAAA
static nsresult dohEncode(nsCString aHost,
                          bool aIpv6,
                          nsAutoCString &body)
{
    nsAutoCString raw;
    const uint8_t DNS_TYPE_AAAA = 28;
    const uint8_t DNS_TYPE_A = 1;
    const uint8_t DNS_CLASS_IN = 1;

    // Header
    raw += '\0';
    raw += '\0'; // 16 bit id
    raw += '\0'; // |QR|   Opcode  |AA|TC|RD|
    raw += '\0'; // |RA|   Z    |   RCODE   |
    raw += '\0';
    raw += 1;    // QDCOUNT (number of entries in the question section)
    raw += '\0';
    raw += '\0'; // ANCOUNT
    raw += '\0';
    raw += '\0'; // NSCOUNT
    raw += '\0';
    raw += '\0'; // ARCOUNT

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
        index = aHost.FindChar('.', offset);
        if (kNotFound != index) {
            dotFound = true;
            labelLength = index - offset;
        } else {
            labelLength = aHost.Length() - offset;
        }
        if (labelLength > 63) {
            // too long label!
            return NS_ERROR_UNEXPECTED;
        }
        raw += static_cast<unsigned char>(labelLength);
        nsDependentCSubstring label = Substring(aHost, offset, labelLength);
        raw.Append(label);
        if(!dotFound) {
            raw += '\0'; // terminate with a final zero
            break;
        }
        offset += labelLength + 1; // move over label and dot
    } while(1);

    raw += '\0'; // upper 8 bit TYPE
    raw += aIpv6 ? DNS_TYPE_AAAA : DNS_TYPE_A;
    raw += '\0'; // upper 8 bit CLASS
    raw += DNS_CLASS_IN;    // IN - "the Internet"

    nsresult rv = Base64Encode(raw, body);
    if (NS_FAILED(rv)) {
        return rv;
    }

    return NS_OK;
}

nsresult TRR::DNSoverHTTPS()
{
    MOZ_ASSERT(NS_IsMainThread(), "wrong thread");
    //
    // 'host' should be converted to a DNS query packet for QTYPE "A" or
    // "AAAA" (based on af), then base64url-encoded and inserted into the URL
    //
    nsresult rv;
    nsCOMPtr<nsIIOService> ios(do_GetIOService(&rv));
    if (NS_FAILED(rv)) {
        return rv;
    }
    nsCOMPtr<nsIChannel> channel;
    nsCOMPtr<nsIURI> dnsURI;

    // :path = /.well-known/dns-query?  (no CR)
    // content-type=application/dns-udpwireformat&  (no CR)
    // body=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB

    // the raw example 'body':
    // 00000000  ab cd 01 00 00 01 00 00  00 00 00 00 03 77 77 77  |.............www|
    // 00000010  07 65 78 61 6d 70 6c 65  03 63 6f 6d 00 00 01 00  |.example.com....|
    // 00000020  01                                                |.|

    // dummy URL for test
    nsAutoCString uri("https://daniel.haxx.se/dns/?body=");
    nsAutoCString body;

    rv = dohEncode(mHostname, mAf == PR_AF_INET6, body);
    if (NS_FAILED(rv)) {
        return rv;
    }
    uri.Append(body);
    //uri.Append("&host="); // send plain host too for the dummy server
    //uri.Append(mHostname);
    NS_NewURI(getter_AddRefs(dnsURI), uri);

    // use GET
    // set "accept:" header
    // make sure this is only done over HTTP/2
    NS_NewChannel(getter_AddRefs(channel),
                  dnsURI,
                  nsContentUtils::GetSystemPrincipal(),
                  nsILoadInfo::SEC_ALLOW_CROSS_ORIGIN_DATA_IS_NULL,
                  nsIContentPolicy::TYPE_OTHER,
                  nullptr, // aLoadGroup
                  nullptr, // aCallbacks
                  nsIRequest::LOAD_NORMAL|nsIRequest::LOAD_ANONYMOUS,
                  ios);

    if (channel) {
        nsCOMPtr<nsIStreamListener> listener = new DOHListener(this);
        if (NS_SUCCEEDED(channel->AsyncOpen2(listener))) {
            return NS_OK;
        }
    }

    return NS_ERROR_UNEXPECTED;
}

NS_IMETHODIMP
DOHListener::OnStartRequest(nsIRequest *aRequest,
                            nsISupports *aContext)
{
    mStartTime = TimeStamp::Now();
    return NS_OK;
}

static uint16_t get16bit(nsCString &aData, int index)
{
    return (static_cast<uint8_t>(aData[index]) << 8) |
        static_cast<uint8_t>(aData[index + 1]);
}

static uint16_t get32bit(nsCString &aData, int index)
{
    return (static_cast<uint8_t>(aData[index]) << 24) |
        (static_cast<uint8_t>(aData[index+1])<<16) |
        (static_cast<uint8_t>(aData[index+2]) << 8) |
        static_cast<uint8_t>(aData[index+3]);
}
//
// dohDecode() collects the TTL and the IP addresses in the response
//
nsresult
DOHListener::dohDecode()
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

    if (mResponse[0] || mResponse[1] || (mResponse.Length() < 0x20)) {
        LOG("TRR bad incoming DOH, eject!\n");
        return NS_ERROR_UNEXPECTED;
    }

    // Figure out the number of answer records from ANCOUNT
    uint16_t records = get16bit(mResponse, 6);

    LOG("TRR Decode: %d records (%u bytes body)\n", records,
        mResponse.Length());

    // iterate over the single host name in question
    do {
        length = static_cast<uint8_t>(mResponse[index]);
        if (length) {
            if (host.Length()) {
                host.Append(".");
            }
            host.Append( Substring(mResponse, index + 1, length) );
        }
        index += 1 + length; // skip length byte + label
    } while (length);
    index += 4; // skip question's type, class

    // ANSWER
    while (records) {

        length = static_cast<uint8_t>(mResponse[index]);
        if ((length & 0xc0) == 0xc0) {
            // name pointer, advance over it
            index += 2;
        } else if (length & 0xc0) {
            // illegal length, bail out
            LOG("TRR: illegal label length byte (%x)\n", length);
            return NS_ERROR_UNEXPECTED;
        }
        else {
            // iterate over host name in answer
            do {
                length = static_cast<uint8_t>(mResponse[index]);
                index += 1 + length;
                LOG("TRR: move over %d bytes\n", 1 + length);
            } while (length);
        }
        // skip type, class
        index += 4;

        // 32 bit TTL (seconds)
        uint32_t TTL = get32bit(mResponse, index);
        index += 4;

        // 16 bit RDLENGTH
        uint16_t RDLENGTH = get16bit(mResponse, index);
        index += 2;

        // RDATA
        // - IPv4 (TYPE 1):  4 bytes
        // - IPv6 (TYPE 28): 16 bytes

        if ((RDLENGTH != 4) && (RDLENGTH != 16)) {
            LOG("TRR received strange RDATA (%u), aborting\n", RDLENGTH);
            return NS_ERROR_UNEXPECTED;
        }
        mDNS.Add(TTL, mResponse, index, RDLENGTH, host);

        index += RDLENGTH;
        records--;
    }

    if (index != mResponse.Length()) {
        LOG("TRRRRRR: bad DNS parser (%u != %d)!\n", index, (int)mResponse.Length());
        // failed to parse 100%, do not continue
        return NS_ERROR_UNEXPECTED;
    }
    return NS_OK;
}

nsresult DOHListener::returnData()
{
    // create and populate an AddrInfo instance to pass on
    AddrInfo *ai = new AddrInfo(mTrr->mHostname.get(), true);
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
    (void)mTrr->mHostResolver->OnLookupComplete(mTrr->mRec, NS_OK, ai);
    LOG("********** TRR data sent to OnLookupComplete!\n");
    return NS_OK;
}

NS_IMETHODIMP
DOHListener::OnStopRequest(nsIRequest *aRequest,
                           nsISupports *aContext,
                           nsresult aStatusCode)
{
    // if status was "fine", parse the response and pass on the answer
    if (NS_OK == aStatusCode) {
        nsCOMPtr<nsIHttpChannel> httpChannel = do_QueryInterface(aRequest);
        if (!httpChannel) {
            return NS_ERROR_UNEXPECTED;
        }
        nsresult rv = NS_OK;
        uint32_t httpStatus;
        rv = httpChannel->GetResponseStatus(&httpStatus);
        if (NS_SUCCEEDED(rv) && httpStatus == 200) {
            // decode body and create an AddrInfo struct for the response
            rv = dohDecode();

            if (NS_SUCCEEDED(rv)) {
                // pass back the response data
                returnData();
            }
        }
        // else
        //   send error back
    }
    return NS_OK;
}

NS_IMETHODIMP
DOHListener::OnDataAvailable(nsIRequest *aRequest,
                             nsISupports *aContext,
                             nsIInputStream *aInputStream,
                             uint64_t aOffset,
                             const uint32_t aCount)
{
    // receive DNS response into the local buffer

    // make sure this is never a big response
    char buf[aCount];
    uint32_t count;
    aInputStream->Read(buf, aCount, &count);
    mResponse.AppendASCII(buf, count);

    return NS_OK;
}

nsresult DOHresp::Add(uint32_t TTL, nsCString &dns, int index, uint16_t len,
                      nsAutoCString & host)
{
    DOHaddr *doh = new DOHaddr;
    NetAddr *addr = &doh->mNet;
    if (4 == len) {
        // IPv4
        addr->inet.family = AF_INET;
        addr->inet.port = 0; // unknown
        addr->inet.ip = get32bit(dns, index);
        LOG("DOH: Add %s %u.%u.%u.%u\n", host.get(), static_cast<uint8_t>(dns[index]),
            static_cast<uint8_t>(dns[index+1]),
            static_cast<uint8_t>(dns[index+2]),
            static_cast<uint8_t>(dns[index+3]));
    } else if (16 == len) {
        // IPv6
        addr->inet6.family = AF_INET6;
        addr->inet6.port = 0;     // unknown
        addr->inet6.flowinfo = 0; // unknown
        addr->inet6.scope_id = 0; // unknown
        for(int i = 0; i < 16; i++, index++) {
            addr->inet6.ip.u8[i] = dns[index];
        }
        LOG("DOH: Add %s AAAA entry\n", host.get());
    } else {
        return NS_ERROR_UNEXPECTED;
    }
    doh->mTtl = TTL;
    mAddresses.insertBack(doh);

    return NS_OK;
}
