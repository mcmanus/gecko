/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "MozQuic.h"
#include "MozQuicInternal.h"
#include "MozQuicStream.h"

#include "assert.h"
#include "stdlib.h"
#include "unistd.h"

namespace mozilla { namespace net {

MozQuicStreamPair::MozQuicStreamPair(uint32_t id, MozQuicWriter *w)
  : mOut(id, w)
  , mIn(id)
{
}

MozQuicStreamPair::~MozQuicStreamPair()
{
}

MozQuicStreamIn::MozQuicStreamIn(uint32_t id)
{
}

MozQuicStreamIn::~MozQuicStreamIn()
{
}

MozQuicStreamOut::MozQuicStreamOut(uint32_t id, MozQuicWriter *w)
  : mWriter(w)
  , mStreamID(id)
  , mOffset(0)
{
}

MozQuicStreamOut::~MozQuicStreamOut()
{
}

uint32_t
MozQuicStreamOut::Write(unsigned char *data, uint32_t len)
{
  std::unique_ptr<MozQuicStreamChunk> tmp(new MozQuicStreamChunk(mStreamID, mOffset, data, len));
  mOffset += len;
  return mWriter->DoWriter(tmp);
}

// todo an interface that doesn't copy would be good
MozQuicStreamChunk::MozQuicStreamChunk(uint32_t id, uint64_t offset,
                                       unsigned char *data, uint32_t len)
  : mData(new unsigned char[len])
  , mLen(len)
  , mStreamID(id)
  , mOffset(offset)
  , mTransmitTime(0)
  , mRetransmitted(false)
{
  memcpy(mData.get(), data, len);
}

MozQuicStreamChunk::~MozQuicStreamChunk()
{
}

}} // namespace
