/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozquicstream_h__
#define mozquicstream_h__

#include <list>
#include <stdint.h>
#include <unistd.h>
#include <memory>
namespace mozilla { namespace net {

class MozQuicStreamChunk
{
public:
  MozQuicStreamChunk(uint32_t id, uint64_t offset, unsigned char *data, uint32_t len);
  ~MozQuicStreamChunk();

  std::unique_ptr<unsigned char []>mData;
  uint32_t mLen;
  uint32_t mStreamID;
  uint64_t mOffset;

  // when unacked these are set
  uint64_t mPacketNum;
  uint64_t mTransmitTime;
  bool     mRetransmitted; // no data after retransmitted
};

class MozQuicWriter 
{
public:
  // the caller owns the unique_ptr if it returns 0
  virtual uint32_t DoWriter(std::unique_ptr<MozQuicStreamChunk> &p) = 0;
};
  
class MozQuicStreamOut
{
public:
  MozQuicStreamOut(uint32_t id, MozQuicWriter *w);
  ~MozQuicStreamOut();
  uint32_t Write(unsigned char *data, uint32_t len);

private:
  MozQuicWriter *mWriter;
  uint32_t mStreamID;
  uint64_t mOffset;
};

class MozQuicStreamIn
{
public:
  MozQuicStreamIn(uint32_t id);
  ~MozQuicStreamIn();
  uint32_t Read();
private:
  std::list<MozQuicStreamChunk> mBuffered;
};

class MozQuicStreamPair
{
public:
  MozQuicStreamPair(uint32_t id, MozQuicWriter *);
  ~MozQuicStreamPair();
    
  uint32_t Read() {
    return mIn.Read();
  }

  uint32_t Write(unsigned char *data, uint32_t len) {
    return mOut.Write(data, len);
  }

  MozQuicStreamOut mOut;
  MozQuicStreamIn  mIn;
};

}} //namespace
#endif
