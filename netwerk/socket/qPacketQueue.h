/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include <stdlib.h>

#define NUM_RETRANSMIT_IDS 3

struct id_t
{
  uint16_t mEpoch;
  uint64_t mSeq;
  PRIntervalTime mSentTime;
};

struct aPacket_t
{
  uint32_t mSize;
  // All ids that this packet is sent with.
  uint64_t mOriginalId; // Holds the first packetId and it does not change on a retransmission.
  struct id_t mIds[NUM_RETRANSMIT_IDS];
  uint32_t mIdsNum;
  uint8_t mForRetransmission;
  uint8_t mIsPingPkt;
  struct aPacket_t *mNext;
  // the buffer lives at the end of the struct
};

struct aPacketQueue_t
{
  struct aPacket_t *mFirst, *mLast;
  uint32_t mLen;
};
