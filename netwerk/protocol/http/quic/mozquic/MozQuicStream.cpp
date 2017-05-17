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
  : mOffset(0)
  , mFinOffset(0)
  , mFinRecvd(false)
{
}

MozQuicStreamIn::~MozQuicStreamIn()
{
}

// returning amt = 0 is not a fin or an error on its own
uint32_t
MozQuicStreamIn::Read(unsigned char *buffer, uint32_t avail, uint32_t &amt, bool &fin)
{
  amt = 0;
  if (mFinRecvd && mFinOffset == mOffset) {
    fin = true;
    return MOZQUIC_OK;
  }
  fin = false;
  if (mAvailable.empty()) {
    return MOZQUIC_OK;
  }

  std::list<std::unique_ptr<MozQuicStreamChunk>>::iterator i = mAvailable.begin();
  if ((*i)->mOffset > mOffset) {
    // no data yet
    return MOZQUIC_OK;
  }
  uint64_t skip = mOffset - (*i)->mOffset;
  unsigned char *src = (*i)->mData.get() + skip;
  uint64_t copyLen = (*i)->mLen - skip;
  if (copyLen > avail) {
    copyLen = avail;
  }
  memcpy (buffer, src, copyLen);
  mOffset += copyLen;
  if (mFinRecvd && mFinOffset == mOffset) {
    fin = true;
  }
  if (mOffset == (*i)->mOffset + (*i)->mLen) {
    // we dont need this buffer anymore
    mAvailable.erase(i);
  }
  return MOZQUIC_OK;
}

uint32_t
MozQuicStreamIn::Supply(std::unique_ptr<MozQuicStreamChunk> &d)
{
  // new frame segment goes into a linked list ordered by seqno
  // any overlapping data is dropped

  if (d->mFin) {
    mFinRecvd = true;
    mFinOffset = d->mOffset + d->mLen;
  }

  // if the list is empty, add it to the list!
  if (mAvailable.empty()) {
    mAvailable.push_front(std::move(d));
    return MOZQUIC_OK;
  }

  // not these are reverse iterators so iter++ moves to the left (earlier seqno)
  // and insert puts new node to the right (later seqno)
  std::list<std::unique_ptr<MozQuicStreamChunk>>::reverse_iterator i = mAvailable.rbegin();
  std::list<std::unique_ptr<MozQuicStreamChunk>>::reverse_iterator end = mAvailable.rend();

  while (i != end) {
    // we don't need empty chunks
    if (!d->mLen) {
      // todo log
      std::unique_ptr<MozQuicStreamChunk> x(std::move(d));
      return MOZQUIC_OK;
    }
    
    // check for dup
    // if i offset && len == d offset && len drop it
    if ((d->mOffset == (*i)->mOffset) && (d->mLen == (*i)->mLen)) {
      // todo log
      // this is a dup. ignore it.
      std::unique_ptr<MozQuicStreamChunk> x(std::move(d));
      return MOZQUIC_OK;
    }

    // check for full append to the right (later seq [d is after i])
    // if i offset + len <= d.offset then append after 
    if (((*i)->mOffset + (*i)->mLen) <= d->mOffset) {
      mAvailable.insert(i.base(), std::move(d));
      return MOZQUIC_OK;
    }

    // check for full location to the left (earlier seq [d is before i])
    // if d offset + len <= i.offset then iter left and rpt
    if ((d->mOffset + d->mLen) <= (*i)->mOffset){
      i++;
      continue;
    }
  
    // d overlaps with i. Form a new chunk with any portion that
    // exists to the right and append that (if it exists), and then
    // adjust the current chunk to only cover data to the left (not
    // any overlap) and iter to the left.
    if ((d->mOffset + d->mLen) > ((*i)->mOffset + (*i)->mLen)) {
      // we need a new chunk
      uint64_t skip = (*i)->mOffset + (*i)->mLen - d->mOffset;
      std::unique_ptr<MozQuicStreamChunk>
        newChunk(new MozQuicStreamChunk(d->mStreamID,
                                        (*i)->mOffset + (*i)->mLen,
                                        d->mData.get() + skip,
                                        d->mLen - skip, false));
      d->mLen = skip;

      // todo log
      // append it to the right
      mAvailable.insert(i.base(), std::move(newChunk));
      // dont continue or return, still need to deal with remainder
    }

    if ((*i)->mOffset <= d->mOffset) {
      // there is no more data to the left. drop it.
      // todo log
      std::unique_ptr<MozQuicStreamChunk> x(std::move(d));
      return MOZQUIC_OK;
    }

    // adjust data to be non overlapping
    d->mLen = (*i)->mOffset - d->mOffset;
    // todo log
    i++;
  }
  
  mAvailable.push_front(std::move(d));
  return MOZQUIC_OK;
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
  std::unique_ptr<MozQuicStreamChunk> tmp(new MozQuicStreamChunk(mStreamID, mOffset, data, len, false));
  mOffset += len;
  return mWriter->DoWriter(tmp);
}

// todo an interface that doesn't copy would be good
MozQuicStreamChunk::MozQuicStreamChunk(uint32_t id, uint64_t offset,
                                       unsigned char *data, uint32_t len,
                                       bool fin)
  : mData(new unsigned char[len])
  , mLen(len)
  , mStreamID(id)
  , mOffset(offset)
  , mFin(fin)
  , mTransmitTime(0)
  , mRetransmitted(false)
{
  memcpy(mData.get(), data, len);
}

MozQuicStreamChunk::~MozQuicStreamChunk()
{
}

}} // namespace
