/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "nspr.h"
#include "prerror.h"
#include "prio.h"
#include "sdt.h"
#include "ssl.h"
#include "unistd.h"

#include "qPacketQueue.h"
#include "sdt_common.h"
#include "congestion_control.h"
#include "tcp_general.h"

// TODO connection reusing

/*
an SDT Socket

// Note: to avoid another buffer copy layer h is not a real layer, but there
// is a couple of function that are called by a layer.

H transform Http2 <-> SDT
A deal with ack info, retransmisions
Q queuelayer (pacing, congestion control, etc..)
C cryptolayer (dtls)
S layer - This implementation uses sequence number from DTLS. S layer is under
          DTLS layer and is responsible remembering sequence number of outgoing
          and incoming packets.

on write -
H from Http2 to SDT
A nop
Q queues (and manages timers) or sends to network - TODO still missing, I have
  not deleted functions from Patrick's implementation, but they are never
  called.
C applies ciphers (dtls from nss)
S read sequence number from DTLS header and store it in packet info of the
  outgoing packet

on read -
S (epoch, seq, etc..) read DTLS sequence number and update structure that
  keeps info about received packets. This structure is use for forming ACKs.
C decrypt (dlts from nss)
Q nop
A The packet can be data or ACK. If it is ACK remove from retransmission queue
  the packets that the ACK is acking, check for retransmissions, FACK(TODO).
  If it is a data packet, make and send an ACK and send data to upper layer.
H from SDT to Http2

TODO add session identifier for mobility.
*/

// TODO sdtlib-internal.h

/* There is an unfortunate amount of standalone (non reuse) C going on in here
   in the hope of maximum reusability. this might actually be a good candidate
   for a different runtime (rust?) and a c ABI layer. (can go do that?) But
   that's premature compared to working on the basics of the protocol atm. */

#define DTLS_TYPE_CHANGE_CIPHER 20
#define DTLS_TYPE_ALERT         21
#define DTLS_TYPE_HANDSHAKE     22
#define DTLS_TYPE_DATA          23

#define HTTP2_FRAME_TYPE_DATA          0x0
#define HTTP2_FRAME_TYPE_HEADERS       0x1
#define HTTP2_FRAME_TYPE_PRIORITY      0x2
#define HTTP2_FRAME_TYPE_RST_STREAM    0x3
#define HTTP2_FRAME_TYPE_SETTINGS      0x4
#define HTTP2_FRAME_TYPE_PUSH_PROMISE  0x5
#define HTTP2_FRAME_TYPE_PING          0x6
#define HTTP2_FRAME_TYPE_GOAWAY        0x7
#define HTTP2_FRAME_TYPE_WINDOW_UPDATE 0x8
#define HTTP2_FRAME_TYPE_CONTINUATION  0x9
#define HTTP2_FRAME_TYPE_ALTSVC        0xA
#define HTTP2_FRAME_TYPE_LAST          0xB

#define HTTP2_FRAME_FLAG_END_STREAM    0x01
#define HTTP2_FRAME_FLAG_END_HEADERS   0x04
#define HTTP2_FRAME_FLAG_PRIORITY      0x20
#define HTTP2_FRAME_FLAG_ACK           0x01

#define HTTP2_SETTINGS_ENABLE_PUSH         0x02
#define HTTP2_SETTINGS_TYPE_MAX_CONCURRENT 0x03
#define HTTP2_SETTINGS_TYPE_INITIAL_WINDOW 0x04
#define HTTP2_SETTINGS_MAX_FRAME_SIZE      0x05

#define HTTP2_HEADERLEN                9

#define SDT_FRAME_TYPE_STREAM              0x80
#define SDT_FRAME_TYPE_STREAM2             0xBF
#define SDT_FRAME_TYPE_ACK                 0x40
#define SDT_FRAME_TYPE_CONGESTION_FEEDBACK 0x20
#define SDT_FRAME_TYPE_PADDING             0x00
#define SDT_FRAME_TYPE_RST_STREAM          0x01
#define SDT_FRAME_TYPE_CONNECTION_CLOSE    0x02
#define SDT_FRAME_TYPE_GOAWAY              0x03
#define SDT_FRAME_TYPE_WINDOW_UPDATE       0x04
#define SDT_FRAME_TYPE_BLOCKED             0x05
#define SDT_FRAME_TYPE_STOP_WAITING        0x06
#define SDT_FRAME_TYPE_PING                0x07
#define SDT_FRAME_TYPE_PRIORITY            0x08

#define SDT_FIN_BIT 0x40

const uint8_t magicHello[] = {
  0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
  0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
  0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a
};

// DEV_ABORT's might actually happen in the wild, but in the lab are more
// likely to be a bug.. so we will abort on them for now, but they need a
// runtime error path too.
#if 1
#define DEV_ABORT(x) do { abort(); } while (0)
#else
#define DEV_ABORT(x) do { } while (0)
#endif

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

#if 0
// DRAGANA: DTLS layer is set in the similar way as a TLS layer so question
// down should have the same answer as any TLS session in FF, except caching
// which connection over sdt were successful. Proxy needs to be fix.
  // how does auth work here?
  // sni? session caching? alpn? allowable suites?
  // can tls for https be removed if e2e?
#endif

static uint32_t aBufferLenMax = 1048576; // number of queued packets

// our standard time unit is a microsecond
static uint64_t qMaxCreditsDefault = 80000; // ums worth of full bucket
static uint64_t qPacingRateDefault =  5000; // send every 2ms (2000ums)

static uint8_t aMaxNumOfRTORetrans = 6;

#define DUPACK_THRESH 3
#define EARLY_RETRANSMIT_FACTOR 0.25

#define MAX_RTO 60000 // 60s
#define MIN_RTO 1000 // 1s

static PRIntervalTime sMinRTO; // MinRTO in interval that we do not need to convert it each time.
static PRIntervalTime sMaxRTO; // MaxRTO in interval that we do not need to convert it each time.

#define RTO_FACTOR 4
#define RTT_FACTOR_ALPHA 0.125
#define RTT_FACTOR_BETA 0.25

static struct tcp_congestion_ops *cc;// = tcp_general;

//static uint32_t amplificationPacket = 2;

// a generic read to recv mapping
int32_t
sdt_useRecv(PRFileDesc *fd, void *aBuf, int32_t aAmount)
{
  return fd->methods->recv(fd, aBuf, aAmount, 0, PR_INTERVAL_NO_WAIT);
}

// a generic write to send mapping
static int32_t
useSendTo1(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  return fd->methods->sendto(fd, aBuf, aAmount, 0, NULL,
                             PR_INTERVAL_NO_WAIT);
}

// a generic send to sendto mapping
static int32_t
useSendTo2(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
           int flags, PRIntervalTime to)
{
  return aFD->methods->sendto(aFD, aBuf, aAmount, flags, NULL, to);
}

int32_t
sdt_notImplemented(PRFileDesc *fd, void *aBuf, int32_t aAmount,
                   int flags, PRNetAddr *addr, PRIntervalTime to)
{
  DEV_ABORT();
  return -1;
}

int32_t
sdt_notImplemented2(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                    int flags, PRIntervalTime to)
{
  DEV_ABORT();
  return -1;
}

int32_t
sdt_notImplemented3(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                    int flags, const PRNetAddr* aAddr, PRIntervalTime to)
{
  DEV_ABORT();
  return -1;
}

static PRStatus
genericClose(PRFileDesc *fd)
{
  PRFileDesc *thisLayer = PR_PopIOLayer(fd, PR_GetLayersIdentity(fd));
  thisLayer->dtor(thisLayer);
  return PR_Close(fd);
}

static void
weakDtor(PRFileDesc *fd)
{
  // do not free the handle associated with secret, this
  // layer is just a weak pointer
  fd->secret = NULL;
  PR_DELETE(fd);
}

void
LogBuffer(const char *label, const unsigned char *data, uint32_t datalen)
{
  return;
  // Max line is (16 * 3) + 10(prefix) + newline + null
  char linebuf[128];
  uint32_t index;
  char *line = linebuf;

  linebuf[127] = 0;
  fprintf(stderr,"%s \n", label);
  for (index = 0; index < datalen; ++index) {
    if (!(index % 16)) {
      if (index) {
        *line = 0;
        fprintf(stderr,"%s\n", linebuf);
      }
      line = linebuf;
      snprintf(line, 128, "%08X: ", index);
      line += 10;
    }
    snprintf(line, 128 - (line - linebuf), "%02X ",
             ((const uint8_t *)(data))[index]);
    line += 3;
  }
  if (index) {
    *line = 0;
    fprintf(stderr,"%s\n", linebuf);
  }
}

struct range_t
{
  uint64_t mStart;
  uint64_t mEnd;
  struct range_t *mNext;
};

enum SDTConnectionState {
  SDT_CONNECTING, // Until DTLS handshake finishes
  SDT_TRANSFERRING,
  SDT_CLOSING
};

enum SDTH2SState {
  SDT_H2S_NEWFRAME,
  SDT_H2S_FILLFRAME,
  SDT_H2S_PADDING
};

struct hStreamInfo_t
{
  uint32_t mStreamId;
  uint64_t mNextOffset;
  uint64_t mWindowSize;
  struct hStreamInfo_t *mNext;
};

struct hFrame_t
{
  uint8_t mType;
  uint64_t mSDTOffset;
  uint16_t mSDTLength;
  uint8_t mLast;
  uint16_t mDataSize;
  uint16_t mDataRead;
  struct hFrame_t* mNext;
  // the buffer lives at the end of the struct
};

struct hStream_t
{
  uint32_t mStreamId;
  uint64_t mSDTOffset;
  uint64_t mWindowSize;
  uint8_t mHeaderDone;
  uint8_t mEnded;
  struct hFrame_t *mFrames;
  struct hStream_t *mNext;
};

struct sdt_t
{
  uint64_t connectionId; // session identifier for mobility. TODO not used now.
  uint8_t publicHeader;
  uint16_t payloadsize;
  uint16_t cleartextpayloadsize;

  PRNetAddr peer;
  uint8_t isConnected;
  uint8_t isServer;

  enum SDTConnectionState state;

  // Not yet transmitted.
  struct aPacketQueue_t aTransmissionQueue;
  // Transmitted not acked.
  struct aPacketQueue_t aRetransmissionQueue;

  // Pkt currently being transferred. This is used for the communication between
  // a and s layer: 1) if it is NULL it is an ack or DTLS handshake packet.
  //                2) not NULL it is new packet or a retransmission.
  struct aPacket_t *aPktTransmit;

  // Max number of outstanding packets (sender buffer size)
  uint32_t mMaxBufferedPkt;

  uint64_t aLargestAcked;
  uint64_t aSmallestUnacked;

  struct range_t *aRecvAckRange; // We are keeping track of the ack ranges that
                                 // a sender has already received from the
                                 // receiver. So we can search
                                 // aRetransmissionQueue only for a diff.
                                 // These are actually ACKed(SACK) ranges not
                                 // NACKed!!! (easier to compare, even though
                                 // we get NACK ranges in an ACK)

  // TODO add this.
  // Let's keep track of acks so that we do not need to go though
  // aRetransmissionQueue for nacked acks. They are not in queue so that will
  // cause the search ti go through the whole queue.
//  uint64_t ackStart; // this is the lowest.
//  unsigned char acks[SDT_REPLAY_WINDOW / 8];

  // Keep track of the largest sent id. This is needed for Early
  // Retransmissions.
  uint8_t aLargestSentEpoch;
  uint64_t aLargestSentId;

  // When a packet is received on slayer we record epoch, seq. number and
  // time.
  uint8_t  sRecvRecordType;
  uint16_t sRecvEpoch;
  uint16_t sRecvDtlsLen;
  uint64_t sRecvSeq;
  uint64_t sBytesRead;
  uint8_t  sLayerSendBuffer[SDT_PAYLOADSIZE_MAX];
  uint64_t sRecvPktId;

  // We always get the whole packet from the network.
  uint8_t aLayerBuffer[SDT_CLEARTEXTPAYLOADSIZE_MAX];
  uint32_t aLayerBufferLen;
  uint32_t aLayerBufferUsed;

  // This is for received packet
  uint8_t aLargestRecvEpoch;
  uint64_t aLargestRecvId;
  PRIntervalTime aLargestRecvTime;
  uint8_t aNumTimeStamps;
  uint64_t aTSSeqNums[10];
  // TODO we can also get rtt for acks, currently partially implemented. Acks
  // have different pkt size, maybe use that. (if we do not need it easy to fix
  // this)
  // We keep last 10 timestamps and this is array is used as a ring.
  PRIntervalTime aTimestamps[10];
  struct range_t *aNackRange; // NACK ranges to send in a ACK
  uint8_t aNeedAck;

  PRIntervalTime aNextToRetransmit;

  PRIntervalTime srtt;
  PRIntervalTime rttvar;
  PRIntervalTime minrtt;
  PRIntervalTime rto;
  uint8_t waitForFirstAck;

  PRIntervalTime RTOTimer; // TODO: this is not really a timer, it is check during poll.
  uint8_t RTOTimerSet;

  PRIntervalTime ERTimer; // TODO: the same as RTOTimer
  uint8_t ERTimerSet;

  PRTime qLastCredit;
  // credits are key in ums
  uint64_t qCredits;
  uint64_t qMaxCredits;
  uint64_t qPacingRate;

  uint16_t hDataLen;
  uint8_t hPadding;
  uint8_t hFlags;
  uint32_t hStream;
  struct hStreamInfo_t *hOutgoingStreams;
  struct hStream_t *hIncomingStreams;
  struct hStream_t *hIncomingHeaders;
  struct hFrame_t *hOrderedFramesLast;
  struct hFrame_t *hOrderedFramesFirst;
  struct hStreamInfo_t *hOutgoingHeaders;
  uint32_t hSDTStreamId;
  uint8_t hType;
  struct hStreamInfo_t *hCurrentStream;
  enum SDTH2SState hState;
  uint64_t hOffsetAll;
  uint8_t hMagicHello;
  uint8_t hSettingRecv;

  uint8_t numOfRTORetrans;

  PRFileDesc *fd; // weak ptr, don't close

  uint64_t aNextPacketId;

  //CUBIC private data
  // This will not work on all platforms, because of the alligment.
  // I will submit this first version and change it later.
  uint64_t cc_general_private[28];
};

void*
sdt_GetCCPrivate(struct sdt_t *sdt)
{
  return sdt->cc_general_private;
}

struct sdt_t *sdt_newHandle()
{
  struct sdt_t *handle = (struct sdt_t *) calloc(sizeof(struct sdt_t), 1);

  if (!handle) {
    return NULL;
  }
  handle->publicHeader = 1 + 8; // connectionId nad packetId
  handle->payloadsize = SDT_PAYLOADSIZE_MAX - 1;
  handle->cleartextpayloadsize = SDT_CLEARTEXTPAYLOADSIZE_MAX - handle->publicHeader;

  handle->state = SDT_CONNECTING;

  handle->mMaxBufferedPkt = aBufferLenMax;

  handle->aNextToRetransmit = 0xffffffffUL;

  handle->rto = sMinRTO;
  handle->numOfRTORetrans = 0;
  handle->waitForFirstAck = 1;

  handle->qMaxCredits = qMaxCreditsDefault;
  handle->qMaxCredits = qPacingRateDefault * 3; // TODO: not use currently
  handle->qPacingRate = qPacingRateDefault;

  handle->hIncomingHeaders =
    (struct hStream_t *) malloc (sizeof(struct hStream_t));

  if (!handle->hIncomingHeaders) {
    goto fail;
  }

  handle->hIncomingHeaders->mFrames = NULL;
  handle->hIncomingHeaders->mSDTOffset = 0;
  // These parameters are ignored for header stream.
  handle->hIncomingHeaders->mWindowSize = 0;
  handle->hIncomingHeaders->mStreamId = 0;
  handle->hIncomingHeaders->mHeaderDone = 0;
  handle->hIncomingHeaders->mEnded = 0;
  handle->hIncomingHeaders->mNext = NULL;

  handle->hOutgoingHeaders =
    (struct hStreamInfo_t *) malloc (sizeof(struct hStreamInfo_t));
  if (!handle->hOutgoingHeaders) {
    goto fail;
  }
  handle->hOutgoingHeaders->mStreamId = 3;
  handle->hOutgoingHeaders->mNextOffset = 0;
  handle->hOutgoingHeaders->mNext = NULL;
  handle->hOutgoingHeaders->mWindowSize = 0;
  handle->hState = SDT_H2S_NEWFRAME;

  handle->aNextPacketId = 1;

  cc->Init(handle);

  return handle;

  fail:
  free(handle->hIncomingHeaders);
  free(handle);
  return NULL;
}


void PacketQueueAddNew(struct aPacketQueue_t *queue, struct aPacket_t *pkt)
{
  pkt->mNext = NULL;
  if (queue->mLen) {
    assert(queue->mFirst);
    assert(queue->mLast);
    assert(!queue->mLast->mNext);
    queue->mLast->mNext = pkt;
    queue->mLast = pkt;
  } else {
    assert(!queue->mFirst);
    assert(!queue->mLast);
    queue->mLast = pkt;
    queue->mFirst = pkt;
  }
  ++queue->mLen;
}

struct aPacket_t *
PacketQueueRemoveFirstPkt(struct aPacketQueue_t *queue)
{
  if (!queue->mFirst) {
    return NULL;
  }

  struct aPacket_t *done = queue->mFirst;
  if (queue->mLast == done) {
    queue->mLast = NULL;
  }
  queue->mFirst = done->mNext;
  --queue->mLen;
  done->mNext = NULL;
  return done;
}

struct aPacket_t *
PacketQueueRemovePktWithId(struct aPacketQueue_t *queue, uint64_t id)
{
  if (!queue->mFirst) {
    return NULL;
  }

  struct aPacket_t *curr = queue->mFirst;
  struct aPacket_t *prev = NULL;

  while (curr) {
    for (uint32_t i = 0; i < curr->mIdsNum; i++) {
      if (curr->mIds[i].mSeq == id) {
        if (prev) {
          prev->mNext = curr->mNext;
        } else {
          queue->mFirst = curr->mNext;
        }
        if (!curr->mNext) {
          queue->mLast = prev;
        }
        curr->mNext = NULL;
        queue->mLen--;
        return curr;
      }
    }
    prev = curr;
    curr = curr->mNext;
  }
  return NULL;
}


void
PacketQueueRemoveAll(struct aPacketQueue_t *queue)
{
  if (!queue->mFirst) {
    return;
  }

  struct aPacket_t *curr = queue->mFirst;
  struct aPacket_t *done;
  while (curr) {
    done = curr;
    curr = curr->mNext;
    free(done);
  }
  queue->mFirst = queue->mLast = NULL;
  queue->mLen = 0;
}

static void
sdt_freeHandle(struct sdt_t *handle)
{

  PacketQueueRemoveAll(&handle->aTransmissionQueue);
  PacketQueueRemoveAll(&handle->aRetransmissionQueue);
  struct range_t *curr = handle->aRecvAckRange;
  struct range_t *done;
  while (curr) {
    done = curr;
    curr = curr->mNext;
    free(done);
  }
  curr = handle->aNackRange;
  while (curr) {
    done = curr;
    curr = curr->mNext;
    free(done);
  }

  struct hStreamInfo_t *doneSI, *currSI = handle->hOutgoingStreams;
  while (currSI) {
    doneSI = currSI;
    currSI = currSI->mNext;
    free(doneSI);
  }
  struct hStream_t *doneS, *currS = handle->hIncomingStreams;
  while (currS) {
    doneS = currS;
    currS = currS->mNext;
    free(doneS);
  }

  struct hFrame_t *doneF, *currF = handle->hOrderedFramesFirst;
  while (currF) {
    doneF = currF;
    currF = currF->mNext;
    free(doneF);
  }

  free(handle->hIncomingHeaders);
  free(handle->hOutgoingHeaders);

  free(handle);
}

uint64_t
FindSmallestUnacked(struct aPacketQueue_t *queue)
{
  if (!queue->mFirst) {
    return 0;
  }

  uint64_t id =queue->mFirst->mOriginalId;
  struct aPacket_t *curr = queue->mFirst->mNext;
  while (curr) {
    if (id > curr->mOriginalId) {
      id = curr->mOriginalId;
    }
    curr = curr->mNext;
  }
  return id;
}

uint16_t
sdt_GetNextTimer(PRFileDesc *fd)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

  uint16_t nextTimer = UINT16_MAX;
  PRIntervalTime now = PR_IntervalNow();

  if (handle->RTOTimerSet && (nextTimer > (handle->RTOTimer - now))) {
    nextTimer = handle->RTOTimer - now;
  }

  if (handle->ERTimerSet && (nextTimer > (handle->ERTimer - now))) {
    nextTimer = handle->ERTimer - now;
  }
  return nextTimer;
}

static unsigned int
sdt_preprocess(struct sdt_t *handle,
               unsigned char *pkt, uint32_t len)
{
  if (len < (13)) {
    DEV_ABORT();
    return 0;
  }

  // sanity check dtls 1.0, 1.1, or 1.2
  if (!((pkt[1] == 0xFE) && (pkt[2] >= 0xFD))) {
    DEV_ABORT();
    return 0;
  }

  // the leading bytes of a dlts record format are 1 byte of type, 2 of tls
  // version, and 64 bits of sequence number

  handle->sRecvRecordType = pkt[0];
  memcpy (&handle->sRecvEpoch, pkt + 3, 2);
  handle->sRecvEpoch = ntohs(handle->sRecvEpoch);

  memcpy (&handle->sRecvSeq, pkt + 7, 4);
  handle->sRecvSeq = ntohl(handle->sRecvSeq);
  handle->sRecvSeq += ((uint64_t)pkt[5]) << 40;
  handle->sRecvSeq += ((uint64_t)pkt[6]) << 32;

  memcpy (&handle->sRecvDtlsLen, pkt + 11, 2);
  handle->sRecvDtlsLen = ntohs(handle->sRecvDtlsLen);

  // we don't allow renogitation which is implied by epoch > 1
  if (handle->sRecvEpoch > 1) {
    DEV_ABORT();
    return 0;
  }
  if (!handle->sRecvEpoch && (handle->sRecvRecordType == DTLS_TYPE_DATA)) {
    // we should only be handshaking in epoch 0
    DEV_ABORT();
    return 0;
  }

  return 1;
}

static PRDescIdentity qIdentity;
static PRDescIdentity sIdentity;
static PRDescIdentity aIdentity;

static PRIOMethods qMethods;
static PRIOMethods sMethods;
static PRIOMethods aMethods;

uint8_t
sLayerPacketReceived(struct sdt_t *handle, uint16_t epoch, uint64_t seq)
{
  uint8_t newPkt = 0;

  if (handle->aLargestRecvEpoch < epoch) {
    handle->aLargestRecvEpoch = epoch;
  }

  fprintf(stderr, "%d sLayerPacketReceived largest receive till now=%lu; this "
          "packet seq=%lu handle=%p\n", PR_IntervalNow(), handle->aLargestRecvId,
          seq, (void *)handle);

  PRIntervalTime now = PR_IntervalNow();

  if (handle->aLargestRecvId < seq) {
    if ((handle->aLargestRecvId + 1) < seq) {

      // there is some packets missing between last largest and the new largest
      // packet id.
      struct range_t *range =
        (struct range_t *) malloc (sizeof(struct range_t));
      range->mStart = handle->aLargestRecvId + 1;
      range->mEnd = seq - 1;
      range->mNext = handle->aNackRange;
      handle->aNackRange = range;
    }
    handle->aLargestRecvId = seq;
    handle->aLargestRecvTime = now;
    newPkt = 1;

  } else {
    struct range_t* curr = handle->aNackRange;
    struct range_t* prev = NULL;
    // Ranges are ordered largerId towards smaller
    while (curr && (curr->mStart > seq)) {
      prev = curr;
      curr = curr->mNext;
    }

    if (!curr || (curr->mEnd < seq)) {
      // Duplicate just ignore it.
      newPkt = 0;

    } else {
      // This packet was NACK previously
      if ((curr->mStart == seq) || (curr->mEnd == seq)) {
        if (curr->mStart != curr->mEnd) {
          if (curr->mStart == seq) {
            curr->mStart = seq + 1;
          } else {
            curr->mEnd = seq - 1;
          }
        } else {
          // This is the only missing packet in a range, delete the range.
          if (prev) {
            prev->mNext = curr->mNext;
          } else {
            handle->aNackRange = curr->mNext;
          }
          free(curr);
        }
      } else {
        // Split the range.
        struct range_t *newRange =
          (struct range_t *) malloc (sizeof(struct range_t));
        newRange->mStart = seq + 1;
        newRange->mEnd = curr->mEnd;
        curr->mEnd = seq -1;
        newRange->mNext = curr;
        if (prev) {
          prev->mNext = newRange;
        } else {
          handle->aNackRange = newRange;
        }
      }

      newPkt = 1;
    }
  }
  if (newPkt) {
    handle->aTSSeqNums[handle->aNumTimeStamps % 10] = seq;
    handle->aTimestamps[handle->aNumTimeStamps % 10] = now;
    handle->aNumTimeStamps++;
    handle->aNumTimeStamps = (handle->aNumTimeStamps == 20) ?
     10 : handle->aNumTimeStamps;
  }
  return newPkt;
}

/**
 *
 *  +--------+
 *  |Flags   |
 *  +--------+--------+--------+--------+--    --+
 *  |ConnectionId (0, 8, 32 or 64)         ...   |
 *  +--------+--------+--------+--------+--    --+
 *  |Paket id (32)                      |
 *  +--------+--------+--------+--------+
 */
#define PUBLIC_FLAG_RESET 0x02
#define CONNECTION_ID_8 0x0C
#define CONNECTION_ID_4 0x08
#define CONNECTION_ID_1 0x04
#define NO_CONNECTION_ID 0x00

static int32_t
sLayerDecodePublicContent(struct sdt_t *handle, unsigned char *buf,
                          int32_t amount)
{
  LogBuffer("To decode: ", buf, amount);
  // For now we do not have connectionID
  assert(!(((uint8_t*)buf)[0] & CONNECTION_ID_8));

  uint64_t id;
  memcpy(&id, buf + 1, 8);
  handle->sRecvPktId = ntohll(id);

  memmove(buf, buf + handle->publicHeader, amount - handle->publicHeader);
  LogBuffer("To decode: ", buf, amount-handle->publicHeader);
  return amount - handle->publicHeader;
}

static uint32_t
sLayerEncodePublicContent(struct sdt_t *handle, const void *buf,
                          int32_t amount)
{
  // this is a quick change to make sdt work with dtls. In the second phase I
  // will adapt tls

  LogBuffer("To encode: ", buf, amount);
  memcpy(handle->sLayerSendBuffer + handle->publicHeader, buf, amount);
  // For now we do not have connectionID
  handle->sLayerSendBuffer[0] = 0x0;
  if ((((uint8_t*)buf)[0]) == DTLS_TYPE_DATA) {
    uint64_t id = htonll(handle->aNextPacketId);
    memcpy(handle->sLayerSendBuffer + 1, &id, 8);
  } else {
    // It is a DTLS handshake packet, for now set id to 0, this will be fixed
    // in the next phase.
    memset(handle->sLayerSendBuffer + 1, 0, 8);
  }

  return amount + handle->publicHeader;
}

static int32_t
sLayerRecv(PRFileDesc *fd, void *buf, int32_t amount,
           int flags, PRIntervalTime to)
{
  int32_t rv = fd->lower->methods->recv(fd->lower, buf, amount, flags, to);

  if (rv < 0) {
    return rv;
  }

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

  handle->sBytesRead += rv;

  rv = sLayerDecodePublicContent(handle, buf, rv);

  if (!sdt_preprocess(handle, buf, rv)) {
    assert(0);
    return -1;
  }

  fprintf(stderr," %dsLayer Recv got %d of ciphertext this=%p "
          "type=%d epoch=%X seq=0x%lX dtlsLen=%d sBytesRead=%ld sRecvPktId:%ld\n",
          PR_IntervalNow(), rv, (void *)handle,
          handle->sRecvRecordType, handle->sRecvEpoch, handle->sRecvSeq,
          handle->sRecvDtlsLen, handle->sBytesRead, handle->sRecvPktId);

  if (handle->sRecvPktId != 0) {
    uint8_t newPkt = sLayerPacketReceived(handle, 0, handle->sRecvPktId);
    if (!newPkt) {
      PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
      rv = -1;
    }
  }

  return rv;
}

static int32_t
sLayerSendTo(PRFileDesc *fd, const void *bufp, int32_t amount,
             int flags, const PRNetAddr *addr, PRIntervalTime to)
{
  if (amount == 0) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  char *buf = (char *)bufp;
  if (!handle) {
    assert (0);
    return -1;
  }

  addr = &(handle->peer);

  if (amount > handle->payloadsize) {
    DEV_ABORT();
    // todo set error
    return -1;
  }

//TODO: this is implemented in this way because I was using it for testing.
  uint32_t epoch = 0;
  memcpy (&epoch, buf + 3, 2);
  epoch = ntohs(epoch);
  uint64_t id = 0;
  memcpy (&id, buf + 7, 4);
  id = ntohl(id);
  id += ((uint64_t)((uint8_t*)buf)[5]) << 40;
  id += ((uint64_t)((uint8_t*)buf)[6]) << 32;

  uint32_t dataLen = sLayerEncodePublicContent(handle, buf, amount);

  int rv = fd->lower->methods->sendto(fd->lower, handle->sLayerSendBuffer,
                                      dataLen, flags, addr, to);

  fprintf(stderr,"%d sLayer send %p %d rv=%d\n", PR_IntervalNow(),
          (void *)handle, amount, rv);

  if (rv < 0) {
    return -1;
  }

  if (rv != dataLen) {
    DEV_ABORT();
    // todo set err
    return -1;
  }

  if ((((uint8_t*)buf)[0]) != DTLS_TYPE_DATA) {
    // It is a DTLS handshake packet.
    return amount;
  }

  if (!handle->aPktTransmit) {
    // It is a ACK.
    handle->aNextPacketId++;
    return amount;
  }

  // Remember last 3 Ids. TODO: 2 is enough
  if (!handle->aPktTransmit->mIdsNum) {
    // Remembre the original id. This is only for debugging.
    handle->aPktTransmit->mOriginalId = handle->aNextPacketId;
  } else if (handle->aPktTransmit->mIdsNum == NUM_RETRANSMIT_IDS) {
    for (int i = 0; i < NUM_RETRANSMIT_IDS -1; i++) {
      handle->aPktTransmit->mIds[i] = handle->aPktTransmit->mIds[i + 1];
    }
    handle->aPktTransmit->mIdsNum--;
  }

  assert(handle->aPktTransmit->mIdsNum < NUM_RETRANSMIT_IDS);
  int inx = handle->aPktTransmit->mIdsNum++;

  handle->aLargestSentEpoch = epoch;
  handle->aLargestSentId = handle->aNextPacketId;

  handle->aPktTransmit->mIds[inx].mEpoch = 0;
  handle->aPktTransmit->mIds[inx].mSeq = handle->aNextPacketId++;
  handle->aPktTransmit->mIds[inx].mSentTime = PR_IntervalNow();

//fprintf(stderr, "Send id: %lu time: %u pkt: %p inx: %d\n", handle->aPktTransmit->mIds[inx].mSeq, handle->aPktTransmit->mIds[inx].mSentTime, handle->aPktTransmit, inx);

  return amount;
}

uint8_t
DoWeNeedToSendAck(struct sdt_t *handle)
{
  // TODO: Decide when we are going to send ack, for each new packet probably,
  // but maybe implement delayACK as well.
  return handle->aNeedAck;
}

struct aPacket_t *
MakeAckPkt(struct sdt_t *handle)
{
  // TODO: For now we are always sanding as much as it can fit in a pkt.
  // To fix:
  // 1) Make possible to send multiple packets if the ack info does not fit
  //    into one.
  // 2) implement STOP_WAITING
  // 3) if number of consecutive lost packet exceed 256, current implementation
  //    will fail. make continues ranges.

  struct aPacket_t *pkt =
    (struct aPacket_t *) malloc (sizeof(struct aPacket_t) +
                                 handle->cleartextpayloadsize);
  pkt->mIdsNum = 0;
  pkt->mNext = NULL;
  pkt->mForRetransmission = 0;
  unsigned char *buf = (unsigned char *)(pkt + 1);

  buf[0] = 0x40;
  buf[1] = 0;
  uint64_t num64 = htonll(handle->aLargestRecvId);

  memcpy(buf + 2, &num64, 8);
  // TODO: fix this. (hint: largestReceicved time delta)
  uint32_t num32 = htonl(PR_IntervalToMicroseconds(PR_IntervalNow() -
                         handle->aLargestRecvTime));
  memcpy(buf + 10, &num32, 4);
  uint8_t numTS = 0;
  uint32_t offset = 15;
  int i = handle->aNumTimeStamps - 1;
  int prevInx = 0;
  for (; i >= 0 && i >= handle->aNumTimeStamps - 10; i--) {
    int inx = i % 10;
    if ((handle->aLargestRecvId - handle->aTSSeqNums[inx]) < 255) {
      buf[offset] = (uint8_t)(handle->aLargestRecvId - handle->aTSSeqNums[inx]);
      offset++;
      if (!numTS) {
        num32 = htonl(PR_IntervalToMicroseconds(PR_IntervalNow() -
                                                handle->aTimestamps[inx]));
      } else {
        num32 = htonl(PR_IntervalToMicroseconds(handle->aTimestamps[prevInx] -
                                                handle->aTimestamps[inx]));
      }
//fprintf(stderr, "MakeAck last %d %d %d %d %d %d\n", handle->aLargestRecvId, handle->aTSSeqNums[inx], ntohl(num32), i, handle->aNumTimeStamps, numTS);
      memcpy(buf + offset, &num32, 4);
      offset += 4;
      prevInx = inx;
      numTS++;
    }
  }
  buf[14] = numTS;
  uint8_t numR = 0;
  if (handle->aNackRange) {
    uint32_t offsetRangeNum = offset;
    offset++;
    buf[0] = 0x60;
    struct range_t *curr = handle->aNackRange;
    struct range_t *prev = NULL;
    uint32_t continuesLeft = 0;
    while (curr && (offset < (handle->cleartextpayloadsize - 9))) {
      if (!numR) {
        num64 = htonll(handle->aLargestRecvId - curr->mEnd);
      } else if (!continuesLeft) {
        num64 = htonll(prev->mStart - curr->mEnd - 1);
      } else {
        num64 = 0;
      }
//fprintf(stderr, "MakeAck range %lu %lu\n", curr->mStart, curr->mEnd);
      memcpy(buf + offset, &num64, 8);
      offset += 8;
      uint64_t rangeLength = (!continuesLeft) ? curr->mEnd - curr->mStart :
                                                continuesLeft;
      if (rangeLength > 256) {
        buf[offset] = 255;
        continuesLeft = rangeLength - 256;
      } else {
        buf[offset] = (uint8_t)(rangeLength);
        prev = curr;
        curr = curr->mNext;
      }
      numR++;
      offset++;
    }
    buf[offsetRangeNum] = numR;
  }
  handle->aNeedAck = 0;
  pkt->mSize = offset;
  return pkt;
}

// r is timeRecv - timeSent and delay is delay at receiver
// srtt uses r and minrtt uses clean rtt r - delay. minrtt still not used,
// maybe not needed, it is from quic.
void
CalculateRTT(struct sdt_t *handle, PRIntervalTime r, PRIntervalTime delay)
{
  // RFC 6298
  PRIntervalTime rwod = r - delay;
  if (handle->waitForFirstAck) {
    handle->waitForFirstAck = 0;
    handle->rttvar = r / 2;
    handle->srtt = r;
    handle->minrtt = rwod;

  } else {

    // Use this measurement only if delay is not greater than rtt.
    if (delay > handle->srtt) {
      return;
    }

    handle->rttvar = (1.0 - RTT_FACTOR_BETA) * handle->rttvar +
                     RTT_FACTOR_BETA * abs(handle->srtt - r);
    handle->srtt = (1.0 - RTT_FACTOR_ALPHA) * handle->srtt +
                   RTT_FACTOR_ALPHA * r;
    handle->minrtt = (1.0 - RTT_FACTOR_ALPHA) * handle->minrtt +
                     RTT_FACTOR_ALPHA * rwod;
  }
  handle->rto = handle->srtt + (((RTO_FACTOR * handle->rttvar) > 1) ?
                               (RTO_FACTOR * handle->rttvar) :
                               1);
  if (handle->rto < sMinRTO) {
    handle->rto = sMinRTO;
  }
  if (handle->rto > sMaxRTO) {
    handle->rto = sMaxRTO;
  }
}

void
MaybeStartRTOTimer(struct sdt_t *handle)
{
  if (!handle->RTOTimerSet) {
    handle->RTOTimerSet = 1;
    handle->RTOTimer = PR_IntervalNow() + handle->rto;
  }
}

void
StopRTOTimer(struct sdt_t *handle)
{
  handle->RTOTimerSet = 0;
}

void
RestartRTOTimer(struct sdt_t *handle)
{
  assert(handle->RTOTimerSet);
  handle->RTOTimer = PR_IntervalNow() + handle->rto;
}

uint8_t
RTOTimerExpired(struct sdt_t *handle, PRIntervalTime now)
{
  return (handle->RTOTimerSet && (handle->RTOTimer < now));
}

void
StartERTimer(struct sdt_t *handle)
{
  handle->ERTimerSet = 1;
  handle->ERTimer = PR_IntervalNow() + handle->srtt * EARLY_RETRANSMIT_FACTOR;
}

uint8_t
ERTimerExpired(struct sdt_t *handle, PRIntervalTime now)
{
  return (handle->ERTimerSet && (handle->ERTimer < now));
}

void
StopERTimer(struct sdt_t *handle)
{
  handle->ERTimerSet = 0;
}

void
NeedRetransmissionDupAck(struct sdt_t *handle)
{
  if (!handle->aTransmissionQueue.mFirst) {
    return;
  }

  struct aPacket_t *curr = handle->aRetransmissionQueue.mFirst;

  while (curr &&
         (handle->aLargestAcked >= (curr->mIds[curr->mIdsNum - 1].mSeq + DUPACK_THRESH))) {

    if (!curr->mForRetransmission) {
      cc->OnPacketLost(handle, curr->mIds[curr->mIdsNum - 1].mSeq,
                       curr->mSize + DTLS_PART + handle->publicHeader);
      curr->mForRetransmission = 1;
    }
    curr = curr->mNext;
  }
}

int8_t
RetransmitQueued(struct sdt_t *handle)
{
  return handle->aRetransmissionQueue.mFirst &&
         handle->aRetransmissionQueue.mFirst->mForRetransmission;
}

int8_t
NeedToSendRetransmit(struct sdt_t *handle)
{
  PRIntervalTime now = PR_IntervalNow();
  return RTOTimerExpired(handle, now) ||
         ERTimerExpired(handle, now) ||
         RetransmitQueued(handle);
}

static int hMakePingAck(struct sdt_t *handle);

struct aAckedPacket_t
{
  uint64_t mId;
  uint32_t mSize;
  PRIntervalTime mRtt;
  uint8_t mHasRtt;
  struct aAckedPacket_t* mNext;
};

static int
RemoveRange(struct sdt_t *handle, uint64_t end, uint64_t start, int numTS,
            uint32_t *tsDelay, uint64_t *tsSeqno,
            struct aAckedPacket_t **acked)
{
  // This function removes range of newly acked packets and updates rtt, rto.

  assert(end >= start);
  // TODO keep track of ACK packets. Because acks are not in retransmission
  // queue search will need to through the whole queue.

  struct aAckedPacket_t *ackedPkts = NULL, *lastPkt = NULL;
  struct aPacket_t *pkt = NULL;
  for (uint64_t i = start; i <= end; i++) {
    pkt = PacketQueueRemovePktWithId(&handle->aRetransmissionQueue, i);

    // We are also acking acks so maybe there is no pkt
    if (pkt) {
      // I expect that numTS should be really small 1-2 (currently it is 10 :)),
      // so this is not that slow and pkt->mIdsNum is in 99.99% of the cases
      // only 1.
      // TODO: this can be optimize  by preprocessing tsDelay and tsSeqno.
      int ts = 0;
      PRIntervalTime rtt = 0;
      uint8_t hasRtt = 0;
      while (!rtt && ts < numTS) {
        // Use this measurement only if delay is not greater than rtt.
        if ((tsDelay[ts] < handle->srtt) || !handle->srtt) {
          for (uint32_t id = 0; id < pkt->mIdsNum; id++) {
            if (pkt->mIds[id].mSeq == tsSeqno[ts]) {
              rtt = PR_IntervalNow() - pkt->mIds[id].mSentTime;
              hasRtt = 1;
              fprintf(stderr, "DDDDD rtt %d delay %d\n", PR_IntervalNow() - pkt->mIds[id].mSentTime, tsDelay[ts]);
              CalculateRTT(handle,
                           PR_IntervalNow() - pkt->mIds[id].mSentTime,
                           tsDelay[ts]);
              break;
            }
          }
        }
        ts++;
      }

      struct aAckedPacket_t *ack =
        (struct aAckedPacket_t *) malloc (sizeof(struct aAckedPacket_t));
      if (!ack) {
        goto cleanup;
      }
      ack->mId = i;
      ack->mSize = pkt->mSize + DTLS_PART + handle->publicHeader;
      ack->mRtt = rtt;
      ack->mHasRtt = hasRtt;
      ack->mNext = NULL;
      if (!lastPkt) {
        ackedPkts = lastPkt = ack;
      } else {
        lastPkt->mNext = ack;
        lastPkt = ack;
      }

      if (pkt->mIsPingPkt) {
        int rc = hMakePingAck(handle);
        if (rc) {
          goto cleanup;
        }
      }
      free(pkt);
    }
  }
  *acked = ackedPkts;
  return 0;

  cleanup:
  free(pkt);
  free(lastPkt);
  *acked = NULL;
  return SDTE_OUT_OF_MEMORY;
}

static int
RecvAck(struct sdt_t *handle, uint8_t type)
{
  fprintf(stderr, "RecvAck [this=%p]\n", (void *)handle);

  assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= 15);

  // If we have a loss reported in the packet, we need to call OnPacketLost
  // before calling OnPacketAcked, because of a cwnd calculation.
  struct aAckedPacket_t *newlyAcked = 0;

  uint8_t hasRanges = (type == 0x60);

  uint64_t largestRecv;

  // Reveived entropy (reveived entropy not implemented)
  handle->aLayerBufferUsed++;

  // The largest received
  memcpy(&largestRecv, handle->aLayerBuffer + handle->aLayerBufferUsed, 8);
  largestRecv = ntohll(largestRecv);
  handle->aLayerBufferUsed += 8;

  if (handle->aLargestAcked > largestRecv) {
    // Out of order ack!!! Ignore it.
    handle->aLayerBufferUsed += 4;
    uint8_t numTS = handle->aLayerBuffer[handle->aLayerBufferUsed];
    handle->aLayerBufferUsed += numTS * 5 + 1;
    if (hasRanges) {
      uint8_t numR = handle->aLayerBuffer[handle->aLayerBufferUsed]; // number of ranges.
      handle->aLayerBufferUsed += numR * 9 + 1;
    }
    return SDTE_OK;
  }

  // Not sure about this.
  handle->aLayerBufferUsed += 4; // Delay at the receiver of the largest observed.

  // Timestamps
  uint8_t numTS =   handle->aLayerBuffer[handle->aLayerBufferUsed];
  assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >=
         (1 + numTS * 5));

  handle->aLayerBufferUsed += 1; // Number of timestamps.
  uint64_t tsSeqno[numTS];
  uint32_t tsDelay[numTS];
  for (int i = 0; i < numTS; i++) {
    uint8_t delta = handle->aLayerBuffer[handle->aLayerBufferUsed];
    handle->aLayerBufferUsed += 1;
    assert(delta <= largestRecv); // TODO change this.

    tsSeqno[i] = largestRecv - delta;
    memcpy(&tsDelay[i], handle->aLayerBuffer + handle->aLayerBufferUsed, 4);
    tsDelay[i] = ntohl(tsDelay[i]);

    if (i) {
      tsDelay[i] += tsDelay[i - 1];
    }
    tsDelay[i] = PR_MicrosecondsToInterval(tsDelay[i]);

    handle->aLayerBufferUsed += 4; // Delay at the receiver.
  }

  if (!hasRanges) {
    // No ranges

    if (handle->aLargestAcked == largestRecv) {
      // dup!!!
      return SDTE_OK;
    }

    int rc = RemoveRange(handle, largestRecv, handle->aLargestAcked + 1,
                         numTS, tsDelay, tsSeqno, &newlyAcked);
    if (rc)
      return rc;
    handle->aLargestAcked = largestRecv;
  } else {

    assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= 1);
    uint8_t numR = handle->aLayerBuffer[handle->aLayerBufferUsed]; // number of ranges.
    handle->aLayerBufferUsed += 1;

    assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= (numR * 9));

    uint64_t num64;
    uint64_t recvRangeStart = largestRecv;
    uint64_t recvRangeEnd = 0;
    struct range_t newRanges[numR + 1];

    int ranges = 0;
    for (int i = 0; i < numR; i++) {

      memcpy(&num64, handle->aLayerBuffer + handle->aLayerBufferUsed, 8);
      handle->aLayerBufferUsed += 8;

      assert(recvRangeStart >= ntohll(num64));

      if (num64 != 0) {
        recvRangeEnd = recvRangeStart - ntohll(num64) + 1;

        newRanges[ranges].mStart = recvRangeStart;
        newRanges[ranges].mEnd = recvRangeEnd;
        ranges++;
        recvRangeStart = recvRangeEnd -
                         handle->aLayerBuffer[handle->aLayerBufferUsed] - 2;
      } else {
        recvRangeStart -= (handle->aLayerBuffer[handle->aLayerBufferUsed] + 1);
      }
      handle->aLayerBufferUsed++;
    }
    newRanges[ranges].mStart = recvRangeStart;
    newRanges[ranges].mEnd = 0;
    ranges++;

    // Compare new and old ranges.
    struct range_t *curr = handle->aRecvAckRange;
    if (!curr) {
      // There was no NACK till now.
      curr = (struct range_t *) malloc (sizeof(struct range_t));
      curr->mNext = NULL;
      curr->mStart = handle->aLargestAcked;
      curr->mEnd = 0;
      handle->aRecvAckRange = curr;
    }
    struct range_t *prev = NULL;

    for (int i = 0; i < ranges; i++) {
      if ((newRanges[i].mStart == curr->mStart) &&
          (newRanges[i].mEnd == curr->mEnd)) {
        // The old one.
        prev = curr;
        curr = curr->mNext;
      } else if (newRanges[i].mEnd > curr->mStart) {
        // completly new one.
        int rc;
        if (!newlyAcked) {
          rc = RemoveRange(handle, newRanges[i].mStart,
                           newRanges[i].mEnd, numTS, tsDelay, tsSeqno,
                           &newlyAcked);
        } else {
          rc = RemoveRange(handle, newRanges[i].mStart,
                           newRanges[i].mEnd, numTS, tsDelay, tsSeqno,
                           &newlyAcked->mNext);
        }
        if (rc)
          return rc;

        struct range_t *newRange =
          (struct range_t *) malloc (sizeof(struct range_t));
        newRange->mStart = newRanges[i].mStart;
        newRange->mEnd = newRanges[i].mEnd;
        newRange->mNext = curr;
        if (prev) {
          prev->mNext = newRange;
        } else {
          handle->aRecvAckRange = newRange;
        }
      } else {
        // NO nacks of ack packet accepted!!!
        assert(newRanges[i].mStart >= curr->mStart);
        assert(newRanges[i].mEnd <= curr->mEnd);

        if (newRanges[i].mStart > curr->mStart) {
          int rc;
          if (!newlyAcked) {
            rc = RemoveRange(handle, newRanges[i].mStart, curr->mStart,
                             numTS, tsDelay, tsSeqno, &newlyAcked);
          } else {
            rc = RemoveRange(handle, newRanges[i].mStart, curr->mStart,
                             numTS, tsDelay, tsSeqno, &newlyAcked->mNext);
          }
          if (rc)
            return rc;
          curr->mStart = newRanges[i].mStart;
        }

        if (newRanges[i].mEnd < curr->mEnd) {
          struct range_t *nextR = curr->mNext;
          assert(nextR); // The last one ends at 0 so this
          while (newRanges[i].mEnd < nextR->mEnd) {

            if (nextR->mStart > newRanges[i].mEnd) {
              // merge 2 ranges
              int rc;
              if (!newlyAcked) {
                rc = RemoveRange(handle, curr->mEnd, nextR->mStart,
                                 numTS, tsDelay, tsSeqno, &newlyAcked);
              } else {
                rc = RemoveRange(handle, curr->mEnd, nextR->mStart,
                                 numTS, tsDelay, tsSeqno, &newlyAcked->mNext);
              }
              if (rc)
                return rc;

              curr->mEnd =  nextR->mEnd;
              curr->mNext = nextR->mNext;
              free(nextR);
            }
          }
        }
        if (newRanges[i].mEnd < curr->mEnd) {
          int rc;
          if (!newlyAcked) {
            rc = RemoveRange(handle, curr->mEnd, newRanges[i].mEnd,
                             numTS, tsDelay, tsSeqno, &newlyAcked);
          } else {
            rc = RemoveRange(handle, curr->mEnd, newRanges[i].mEnd,
                             numTS, tsDelay, tsSeqno, &newlyAcked->mNext);
          }
          if (rc)
            return rc;

          curr->mEnd = newRanges[i].mEnd;
        }
        prev = curr;
        curr = curr->mNext;
      }
    }
    handle->aLargestAcked = largestRecv;
  }

  if (handle->aLayerBufferLen == handle->aLayerBufferUsed) {
    handle->aLayerBufferLen = handle->aLayerBufferUsed = 0;
  }

  if (newlyAcked) {
    NeedRetransmissionDupAck(handle);

    uint64_t oldSmallestUnacked = handle->aSmallestUnacked;
    if ((handle->aRetransmissionQueue.mLen == 0)) {
      // All packets are acked stop RTO timer.
      StopRTOTimer(handle);
      StopERTimer(handle);
      handle->aSmallestUnacked = handle->aLargestAcked + 1;
    } else {
      // Some new packet(s) are acked - restart rto timer.
      RestartRTOTimer(handle);
      if (hasRanges) {
        // This can be done more efficiently!!!
        handle->aSmallestUnacked = FindSmallestUnacked(&handle->aRetransmissionQueue);
        assert(handle->aSmallestUnacked);
      } else {
        handle->aSmallestUnacked = handle->aLargestAcked;
      }
    }

    if (hasRanges && oldSmallestUnacked < handle->aSmallestUnacked) {
      // Send Stop waiting!
      // Maybe swend stop waiting only if a whole range is asked.
      // also after e.g. 2 retransmissions.
    }
    struct aAckedPacket_t *curr = newlyAcked;
    while (curr) {
      newlyAcked = newlyAcked->mNext;
      cc->OnPacketAcked(handle, curr->mId, handle->aSmallestUnacked,
                        curr->mSize, curr->mRtt, curr->mHasRtt);
      free(curr);
      curr = newlyAcked;
    }
  }

  if ((handle->aRetransmissionQueue.mLen) &&
      (handle->aLargestSentId == handle->aLargestAcked)) {
    StartERTimer(handle);
  }
  return SDTE_OK;
}

void
CheckRetransmissionTimers(struct sdt_t *handle)
{
  if (ERTimerExpired(handle, PR_IntervalNow())) {
    fprintf(stderr, "ERTimerExpired\n");
    assert(handle->aRetransmissionQueue.mFirst);
    struct aPacket_t *pkt = handle->aRetransmissionQueue.mFirst;
    if (!pkt->mForRetransmission) {
      cc->OnPacketLost(handle, pkt->mIds[pkt->mIdsNum - 1].mSeq,
        pkt->mSize + DTLS_PART + handle->publicHeader);
      pkt->mForRetransmission = 1;
    }
    StopERTimer(handle);

  } else if (RTOTimerExpired(handle, PR_IntervalNow())) {
    fprintf(stderr, "RTOTimerExpired\n");
    assert(handle->aRetransmissionQueue.mFirst);
    struct aPacket_t *curr = handle->aRetransmissionQueue.mFirst;
    // Mare all for retransmission.
    while (curr) {
      curr->mForRetransmission = 1;
      curr = curr->mNext;
    }
    handle->rto *= 2;
    handle->numOfRTORetrans++;
    cc->OnRetransmissionTimeout(handle);
    // This is a bit incorrect, but it is ok. We  should restart it when we do
    // resend this pkt.
    RestartRTOTimer(handle);
  }
}

static struct hStreamInfo_t*
hFindOutgoingStream(struct sdt_t *handle, uint32_t streamId)
{
  struct hStreamInfo_t *prev = 0, *curr = handle->hOutgoingStreams;
  while (curr && (curr->mStreamId < streamId)) {
    prev = curr;
    curr = curr->mNext;
  }
  if (!curr || (curr->mStreamId != streamId)) {
    struct hStreamInfo_t *stream =
      (struct hStreamInfo_t *) malloc (sizeof(struct hStreamInfo_t));
    stream->mStreamId = streamId;
    stream->mNextOffset = 0;
    stream->mWindowSize = (2 << 16) - 1;
    stream->mNext = curr;
    if (!prev) {
      handle->hOutgoingStreams = stream;
    } else {
      prev->mNext = stream;
    }
    curr = stream;
  }
  return curr;
}

static struct hStream_t*
hFindStream(struct sdt_t *handle, uint32_t streamId)
{
  struct hStream_t *prev = 0, *curr = handle->hIncomingStreams;
  while (curr && (curr->mStreamId < streamId)) {
    prev = curr;
    curr = curr->mNext;
  }
  if (!curr || (curr->mStreamId != streamId)) {
    struct hStream_t *stream =
      (struct hStream_t*) malloc (sizeof(struct hStream_t));
    stream->mStreamId = streamId;
    stream->mSDTOffset = 0;
    stream->mWindowSize = (2 << 16) - 1;
    stream->mHeaderDone = 0;
    stream->mFrames = 0;
    stream->mNext = curr;
    if (!prev) {
      handle->hIncomingStreams = stream;
    } else {
      prev->mNext = stream;
    }
    curr = stream;
  }
  return curr;
}

static void
hRemoveStream(struct sdt_t *handle, uint32_t streamId)
{
  struct hStream_t *prev = 0, *curr = handle->hIncomingStreams;
  while (curr && (curr->mStreamId < streamId)) {
    prev = curr;
    curr = curr->mNext;
  }
  if (!curr || (curr->mStreamId != streamId)) {
    fprintf(stderr, "hRemoveStream no stream %d", streamId);
    return;
  }

  if (!prev) {
    handle->hIncomingStreams = curr->mNext;
  } else {
    prev->mNext = curr->mNext;
  }
  free(curr);
}

static void
hOrderFrameToStream(struct hStream_t* stream, struct hFrame_t *frame)
{
  if (frame->mSDTOffset < stream->mSDTOffset) {
    // It is a dup.
    assert((frame->mSDTOffset + frame->mSDTLength) <= stream->mSDTOffset);
    free(frame);
    return;
  }

  fprintf(stderr, "hOrderFrameToStream %lu %d\n", frame->mSDTOffset,
          frame->mSDTLength);

  struct hFrame_t *prev = 0, *curr = stream->mFrames;
  while (curr && (curr->mSDTOffset < frame->mSDTOffset)) {
    prev = curr;
    curr = curr->mNext;
  }

  if (curr && (curr->mSDTOffset == frame->mSDTOffset)) {
    // It is a dup.
    assert(curr->mSDTLength == frame->mSDTLength);
    free(frame);
    return;
  }

  assert(!curr || ((frame->mSDTOffset + frame->mSDTLength) <= curr->mSDTOffset));
  assert(!prev || ((prev->mSDTOffset + prev->mSDTLength) <= frame->mSDTOffset));
  frame->mNext = curr;
  if (!prev) {
    stream->mFrames = frame;
  } else {
    prev->mNext = frame;
  }
}

// This frames are ready to be given to Http2.
static void
hAddSortedHttp2Frame(struct sdt_t *handle, struct hFrame_t *frame)
{
  assert(!frame->mNext);
  // This are not ordered.
  if (handle->hOrderedFramesLast) {
    handle->hOrderedFramesLast->mNext = frame;
  } else {
    handle->hOrderedFramesFirst = frame;
  }
  handle->hOrderedFramesLast = frame;
}

static void
hOrderStreamFrame(struct sdt_t *handle, struct hFrame_t *frame,
                  uint32_t streamId)
{
  fprintf(stderr, "hOrderStreamFrame \n");

  assert(!frame->mNext);

  struct hStream_t* stream = hFindStream(handle, streamId);

  // Add frame.
  hOrderFrameToStream(stream, frame);

  // Check if we have some ordered packets.
  while (stream->mFrames && (stream->mSDTOffset == stream->mFrames->mSDTOffset)) {
    struct hFrame_t *frameOrd = stream->mFrames;

    stream->mFrames = stream->mFrames->mNext;
    frameOrd->mNext = NULL;
    stream->mSDTOffset += frameOrd->mSDTLength;
    stream->mEnded = frameOrd->mLast;
    assert(!stream->mEnded || !stream->mFrames);

    fprintf(stderr, "hOrderStreamFrame one done %lu %d\n",
            frameOrd->mSDTOffset, frameOrd->mSDTLength);

    hAddSortedHttp2Frame(handle, frameOrd);
  }
  if (stream->mEnded) {
    hRemoveStream(handle, streamId);
  }
}

static void
hOrderHeaderFrame(struct sdt_t *handle, struct hFrame_t *frame)
{
  fprintf(stderr, "hOrderHeaderFrame\n");

  assert(!frame->mNext);

  // Add frame.
  hOrderFrameToStream(handle->hIncomingHeaders, frame);

  // Check if we have some ordered packets.
  while (handle->hIncomingHeaders->mFrames &&
         (handle->hIncomingHeaders->mSDTOffset ==
          handle->hIncomingHeaders->mFrames->mSDTOffset)) {
    uint8_t *frame = (uint8_t *)(handle->hIncomingHeaders->mFrames + 1);
    uint8_t type = frame[3];
    uint8_t flags = frame[4];
    assert((type == HTTP2_FRAME_TYPE_HEADERS) ||
           (type == HTTP2_FRAME_TYPE_CONTINUATION));

    uint32_t streamId;
    memcpy(&streamId, frame + 5, 4);
    streamId = ntohl(streamId);
    assert((streamId != 1) && (streamId != 3));
    if (streamId % 2) {
      streamId -= 4;
    }

    struct hStream_t* stream = NULL;
    if ((flags & HTTP2_FRAME_FLAG_END_STREAM) ||
        (flags & HTTP2_FRAME_FLAG_END_HEADERS)) {
      stream = hFindStream(handle, streamId);
      stream->mHeaderDone = flags & HTTP2_FRAME_FLAG_END_HEADERS;
      stream->mEnded = flags & HTTP2_FRAME_FLAG_END_STREAM;
    }

    uint32_t streamIdNet = htonl(streamId);
    memcpy(frame + 5, &streamIdNet, 4);

    struct hFrame_t *doneFrame = handle->hIncomingHeaders->mFrames;
    handle->hIncomingHeaders->mFrames = handle->hIncomingHeaders->mFrames->mNext;
    handle->hIncomingHeaders->mSDTOffset += doneFrame->mSDTLength;
    doneFrame->mNext = NULL;

    fprintf(stderr, "hOrderHeaderFrame one done %lu %d\n",
            doneFrame->mSDTOffset, doneFrame->mSDTLength);

    hAddSortedHttp2Frame(handle, doneFrame);

    if (stream && stream->mHeaderDone && stream->mEnded) {
      assert(!stream->mFrames);
      hRemoveStream(handle, streamId);
    }
  }
}

static void
hMakeMagicFrame(struct sdt_t *handle)
{
  struct hFrame_t *frame = (struct hFrame_t*) malloc (sizeof(struct hFrame_t) +
                                                      24);
  frame->mNext = 0;
  frame->mSDTOffset = 0;
  frame->mSDTLength = 0;
  frame->mDataSize = 24;
  frame->mDataRead = 0;
  frame->mLast = 0;

  uint8_t *framebuf = (uint8_t*)(frame + 1);
  memcpy(framebuf, magicHello, 24);
  hAddSortedHttp2Frame(handle, frame);
}

static void
hMakeSettingsSettingsAckFrame(struct sdt_t *handle, uint8_t ack)
{
  uint16_t frameLen = HTTP2_HEADERLEN + (ack ? 0 : 6);

  struct hFrame_t *frame = (struct hFrame_t*) malloc (sizeof(struct hFrame_t) +
                                                      frameLen);
  frame->mNext = 0;
  frame->mSDTOffset = 0;
  frame->mSDTLength = 0;
  frame->mDataSize = 0;
  frame->mDataRead = 0;
  frame->mLast = 0;

  uint8_t *framebuf = (uint8_t*)(frame + 1);

  framebuf[frame->mDataSize] = 0;
  frame->mDataSize += 1;

  uint16_t len = ack ? 0 : 6;
  len = htons(len);
  memcpy(framebuf + frame->mDataSize, &len, 2);
  frame->mDataSize += 2;

  framebuf[frame->mDataSize] = HTTP2_FRAME_TYPE_SETTINGS;
  frame->mDataSize++;

  if (ack) {
    framebuf[frame->mDataSize] = HTTP2_FRAME_FLAG_ACK; //ACK
  } else {
    framebuf[frame->mDataSize] = 0;
  }
  frame->mDataSize++;

  uint32_t id = 0;
  memcpy(framebuf + frame->mDataSize, &id, 4);
  frame->mDataSize += 4;

  if (!ack) {
    framebuf[frame->mDataSize] = 0;
    framebuf[frame->mDataSize + 1] = HTTP2_SETTINGS_TYPE_INITIAL_WINDOW;
    uint32_t val = htonl(1048576);
    memcpy(framebuf + frame->mDataSize + 2, &val, 4);
    frame->mDataSize += 6;
  }
  hAddSortedHttp2Frame(handle, frame);
}

static int
hMakePingAck(struct sdt_t *handle)
{
  // Ping paket was been acked send an h2 ping ack.
  fprintf(stderr, "Send HTTP2 PING ACK.\n");
  struct hFrame_t *frame =
    (struct hFrame_t*)malloc(sizeof(struct hFrame_t) +
                             HTTP2_HEADERLEN + 8);
  if (!frame)
    return SDTE_OUT_OF_MEMORY;

  frame->mNext = 0;
  frame->mSDTOffset = 0;
  frame->mSDTLength = 0;
  frame->mDataSize = HTTP2_HEADERLEN + 8;
  frame->mDataRead = 0;
  frame->mLast = 0;

  uint8_t *buf = (uint8_t*)(frame + 1);
  buf[0] = 0;
  uint16_t len = htons(8);
  memcpy(buf + 1, &len, 2);
  buf[3] = HTTP2_FRAME_TYPE_PING;
  buf[4] = HTTP2_FRAME_FLAG_ACK;
  memset(buf + HTTP2_HEADERLEN, 0, 8);
  hAddSortedHttp2Frame(handle, frame);
  return 0;
}

static int
sdt2h2(struct sdt_t *handle)
{
  LogBuffer("sdt2h2 buffer ", handle->aLayerBuffer,
            handle->aLayerBufferLen );

  // If there is no magic sent we need to sent it and settings too.
  if (!handle->hMagicHello) {
    handle->hMagicHello = 1;
    hMakeMagicFrame(handle);
    hMakeSettingsSettingsAckFrame(handle, 0);
  }

  while ((handle->aLayerBufferLen - handle->aLayerBufferUsed) > 0) {
    uint8_t type = handle->aLayerBuffer[handle->aLayerBufferUsed];
    handle->aLayerBufferUsed++;
    if (type & SDT_FRAME_TYPE_STREAM) {
      fprintf(stderr, "SDT_SDT_FRAME_TYPE_STREAM received\n");
      // This is a stream frame.
      handle->aNeedAck = 1;
      assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= 14);
      uint32_t streamId;
      memcpy(&streamId, handle->aLayerBuffer + handle->aLayerBufferUsed, 4);
      streamId = ntohl(streamId);
      handle->aLayerBufferUsed += 4;
      uint64_t offset;
      memcpy(&offset, handle->aLayerBuffer + handle->aLayerBufferUsed, 8);
      offset = ntohll(offset);
      handle->aLayerBufferUsed += 8;
      uint16_t len;
      memcpy(&len, handle->aLayerBuffer + handle->aLayerBufferUsed, 2);
      len = ntohs(len);
      handle->aLayerBufferUsed += 2;
      assert(len <= (handle->aLayerBufferLen - handle->aLayerBufferUsed));

      struct hFrame_t *frame =
        (struct hFrame_t*)malloc(sizeof(struct hFrame_t) + len +
                                 ((streamId == 3) ? 0 : HTTP2_HEADERLEN));
      frame->mNext = 0;
      frame->mSDTOffset = offset;
      frame->mSDTLength = len;
      frame->mDataSize = len + ((streamId == 3) ? 0 : HTTP2_HEADERLEN);
      frame->mDataRead = 0;
      frame->mLast = 0;

      if (streamId == 3) {
        // It is a header.
        fprintf(stderr, "SDT_FRAME_TYPE_STREAM received a header frame.\n");
        frame->mType = HTTP2_FRAME_TYPE_HEADERS;

        uint8_t *buf = (uint8_t*)(frame + 1);
        memcpy(buf, handle->aLayerBuffer + handle->aLayerBufferUsed, len);
        handle->aLayerBufferUsed += len;
        // Rewritting of id will be done later;
        hOrderHeaderFrame(handle, frame);

      } else {
        fprintf(stderr, "SDT_FRAME_TYPE_STREAM received a data frame.\n");
        frame->mType = HTTP2_FRAME_TYPE_DATA;
        frame->mLast = !!(type & 0x40);

        uint8_t *buf = (uint8_t*)(frame + 1);
        memcpy(buf + HTTP2_HEADERLEN,
               handle->aLayerBuffer + handle->aLayerBufferUsed, len);
        handle->aLayerBufferUsed += len;
        buf[0] = 0;
        len = htons(len);
        memcpy(buf + 1, &len, 2);
        buf[3] = HTTP2_FRAME_TYPE_DATA;
        buf[4] = (frame->mLast) ? HTTP2_FRAME_FLAG_END_STREAM : 0;

        assert((streamId != 1) && (streamId != 3));
        if (streamId % 2) {
          streamId -= 4;
        }
        uint32_t streamIdN = htonl(streamId);
        memcpy(buf + 5, &streamIdN, 4);

        hOrderStreamFrame(handle, frame, streamId);
      }
    } else if (type & SDT_FRAME_TYPE_ACK) {
      // This is an ACK frame.
      fprintf(stderr, "SDT_FRAME_TYPE_ACK received\n");
      int rc = RecvAck(handle, type);
      if (rc)
        return rc;
    } else if (type & SDT_FRAME_TYPE_CONGESTION_FEEDBACK) {
      // This is CONGESTION_FEEDBACK.
      // Currently not implemented, ignore frame.
      // I assume it has only type field.
      fprintf(stderr, "SDT_FRAME_TYPE_STOP_CONGESTION_FEEDBACK received.\n");
      handle->aNeedAck = 1;
    } else {
      handle->aNeedAck = 1;
      switch (type) {
        case SDT_FRAME_TYPE_PADDING:
          // Ignore the rest of the packet.
          fprintf(stderr, "SDT_FRAME_TYPE_PADDING received.\n");
          handle->aLayerBufferUsed = 0;
          handle->aLayerBufferLen = 0;
          break;
        case SDT_FRAME_TYPE_RST_STREAM:
          {
            fprintf(stderr, "SDT_FRAME_TYPE_RST_STREAM received.\n");
            assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >=
                   (4 + 8 + 4));
            // I am going to queue this one as if it is a data packet
            struct hFrame_t *frame =
              (struct hFrame_t*)malloc(sizeof(struct hFrame_t) +
                                       HTTP2_HEADERLEN + 4);
            frame->mType = HTTP2_FRAME_TYPE_RST_STREAM;
            frame->mNext = 0;
            frame->mSDTOffset = 0;
            frame->mSDTLength = 0;
            frame->mDataSize = HTTP2_HEADERLEN + 4;
            frame->mDataRead = 0;
            frame->mLast = 1;

            uint32_t streamId;
            memcpy(&streamId, handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            streamId = ntohl(streamId);
            handle->aLayerBufferUsed += 4;
            memcpy(&frame->mSDTOffset,
                   handle->aLayerBuffer + handle->aLayerBufferUsed,
                   8);
            frame->mSDTOffset = ntohll(frame->mSDTOffset);

            handle->aLayerBufferUsed += 8;
            uint8_t *buf = (uint8_t*)(frame + 1);
            buf[0] = 0;
            uint16_t lenN = htons(4);
            memcpy(buf + 1, &lenN, 2);
            buf[3] = HTTP2_FRAME_TYPE_RST_STREAM;
            buf[4] = 0;
            assert((streamId != 1) && (streamId != 3));
            if (streamId % 2) {
              streamId -= 4;
            }
            uint32_t streamIdN = htonl(streamId);
            memcpy(buf + 5, &streamIdN, 4);
            memcpy(buf + HTTP2_HEADERLEN,
                   handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            handle->aLayerBufferUsed += 4;

            hOrderStreamFrame(handle, frame, streamId);
            break;
          }
        case SDT_FRAME_TYPE_CONNECTION_CLOSE:
          // We are closing connection
          fprintf(stderr, "SDT_FRAME_TYPE_CONNECTION_CLOSE received.\n");
          handle->state = SDT_CLOSING;
          return SDTE_OK;
        case SDT_FRAME_TYPE_GOAWAY:
          {
            fprintf(stderr, "SDT_FRAME_TYPE_GOWAY received\n");
            // TODO: Check if there is new streams not given to the application.

            // Get the length of error message.
            uint16_t len;
            memcpy(&len,
                   handle->aLayerBuffer + handle->aLayerBufferUsed + 8, 2);
            len = ntohs(len);
            assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >=
                   (8 + 2 + len));
            struct hFrame_t *frame =
              (struct hFrame_t*)malloc(sizeof(struct hFrame_t) +
                                       HTTP2_HEADERLEN + 8 + len);
            frame->mType = HTTP2_FRAME_TYPE_GOAWAY;
            frame->mNext = 0;
            frame->mSDTOffset = 0;
            frame->mSDTLength = 0;
            frame->mDataSize = HTTP2_HEADERLEN + 8 + len;
            frame->mDataRead = 0;
            frame->mLast = 0;

            uint8_t *buf = (uint8_t*)(frame + 1);

            buf[0] = 0;
            uint16_t lenN = htons(8 + len);
            memcpy(buf + 1, &lenN, 2);
            buf[3] = HTTP2_FRAME_TYPE_GOAWAY;
            buf[4] = 0;
            memset(buf + 5, 0, 4);

            uint32_t streamId;
            memcpy(&streamId,
                   handle->aLayerBuffer + handle->aLayerBufferUsed + 4, 4);
            streamId = ntohl(streamId);
            assert((streamId != 1) && (streamId != 3));
            if (streamId % 2) {
              streamId -= 4;
            }
            streamId = htonl(streamId);
            memcpy(buf + HTTP2_HEADERLEN, &streamId, 4);
            memcpy(buf + HTTP2_HEADERLEN + 4,
                   handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            handle->aLayerBufferUsed += 8;

            memcpy(buf + 17,
                   handle->aLayerBuffer + handle->aLayerBufferUsed,
                   len);
            handle->aLayerBufferUsed += 2;
            handle->aLayerBufferUsed += len;
            hAddSortedHttp2Frame(handle, frame);
          }
          break;

        case SDT_FRAME_TYPE_WINDOW_UPDATE:
          {
            // we assume that init window is 16,384
            fprintf(stderr, "SDT_FRAME_TYPE_WINDOW_UPDATE received.\n");
            assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >=
                   12);
            uint32_t streamId;
            memcpy(&streamId,
                   handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            handle->aLayerBufferUsed += 4;
            streamId = ntohl(streamId);

            assert((streamId != 1) && (streamId != 3));

            if (streamId % 2) {
              streamId -= 4;
            }

            struct hStreamInfo_t *streamInfo = hFindOutgoingStream(handle,
                                                                   streamId);

            if (!streamInfo) {
              // ignore
              fprintf(stderr, "No record for stream %d\n", streamId);
              handle->aLayerBufferUsed += 8;
            } else {
              uint64_t offset;
              memcpy(&offset, handle->aLayerBuffer + handle->aLayerBufferUsed,
                     8);
              offset = ntohll(offset);
              handle->aLayerBufferUsed += 8;

              // ignore if the offset is smaller then mWindowSize.
              if (offset > streamInfo->mWindowSize) {
                struct hFrame_t *frame =
                  (struct hFrame_t*)malloc(sizeof(struct hFrame_t) +
                                           HTTP2_HEADERLEN + 4);
                frame->mNext = 0;
                frame->mSDTOffset = 0;
                frame->mSDTLength = 0;
                frame->mDataSize = HTTP2_HEADERLEN + 4;
                frame->mDataRead = 0;
                frame->mLast = 0;
                uint8_t *buf = (uint8_t*)(frame + 1);
                buf[0] = 0;
                uint16_t len = htons(4);
                memcpy(buf + 1, &len, 2);
                buf[3] = HTTP2_FRAME_TYPE_WINDOW_UPDATE;
                buf[4] = 0;

                streamId = htonl(streamId);
                memcpy(buf + 5, &streamId, 4);

                assert((offset - streamInfo->mWindowSize) < (2ll << 32));
                uint32_t increase = offset - streamInfo->mWindowSize;
                increase = htonl(increase);
                streamInfo->mWindowSize = offset;
                memcpy(buf + HTTP2_HEADERLEN, &increase, 4);
                hAddSortedHttp2Frame(handle, frame);
              }
            }
          }
          break;

        case SDT_FRAME_TYPE_BLOCKED:
          {
            fprintf(stderr, "SDT_FRAME_TYPE_BLOCKED received.\n");
            assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= 4);
            uint32_t streamId;
            memcpy(&streamId,
                   handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            streamId = ntohl(streamId);
            handle->aLayerBufferUsed += 4;

            fprintf(stderr, "SDT_FRAME_TYPE_BLOCKED received. Stream id: %d\n",
                    streamId);
            break;
          }
        case SDT_FRAME_TYPE_STOP_WAITING:
          // TODO
          fprintf(stderr, "SDT_FRAME_TYPE_STOP_WAITING received.\n");
          assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= 8);
          handle->aLayerBufferUsed += 4;
          break;

        case SDT_FRAME_TYPE_PING:
          {
            // Propagate PING to h2.
            fprintf(stderr, "SDT_FRAME_TYPE_PING received.\n");
            struct hFrame_t *frame =
              (struct hFrame_t*)malloc(sizeof(struct hFrame_t) +
                                       HTTP2_HEADERLEN + 8);
            frame->mNext = 0;
            frame->mSDTOffset = 0;
            frame->mSDTLength = 0;
            frame->mDataSize = HTTP2_HEADERLEN + 8;
            frame->mDataRead = 0;
            frame->mLast = 0;

            uint8_t *buf = (uint8_t*)(frame + 1);
            buf[0] = 0;
            uint16_t len = htons(8);
            memcpy(buf + 1, &len, 2);
            buf[3] = HTTP2_FRAME_TYPE_PING;
            buf[4] = 0;
            memset(buf + HTTP2_HEADERLEN, 0, 8);
            hAddSortedHttp2Frame(handle, frame);
          }
          break;

        case SDT_FRAME_TYPE_PRIORITY:
          {
            fprintf(stderr, "SDT_FRAME_TYPE_PRIORITY received.\n");
            // Priority is not described readly.(there are 2 versions)
            assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >=
                   4 + 5);
            uint32_t streamId;
            memcpy(&streamId,
                   handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            handle->aLayerBufferUsed += 4;
            streamId = ntohl(streamId);

            assert((streamId != 1) && (streamId != 3));

            if (streamId % 2) {
              streamId -= 4;
            }

            struct hFrame_t *frame =
              (struct hFrame_t*)malloc(sizeof(struct hFrame_t) +
                                       HTTP2_HEADERLEN + 5);
            frame->mNext = 0;
            frame->mSDTOffset = 0;
            frame->mSDTLength = 0;
            frame->mDataSize = HTTP2_HEADERLEN + 5;
            frame->mDataRead = 0;
            frame->mLast = 0;

            uint8_t *buf = (uint8_t*)(frame + 1);
            buf[0] = 0;
            uint16_t len = htons(5);
            memcpy(buf + 1, &len, 2);
            buf[3] = HTTP2_FRAME_TYPE_PRIORITY;
            buf[4] = 0;

            streamId = htonl(streamId);
            memcpy(buf + 5, &streamId, 4);

            memcpy(buf + HTTP2_HEADERLEN,
                   handle->aLayerBuffer + handle->aLayerBufferUsed,
                   5);
            handle->aLayerBufferUsed += 5;
            hAddSortedHttp2Frame(handle, frame);
          }
          break;
      }
    }
  }
  assert(handle->aLayerBufferLen == handle->aLayerBufferUsed);
  handle->aLayerBufferLen = 0;
  handle->aLayerBufferUsed = 0;
  return SDTE_OK;
}

static int32_t
aLayerRecv(PRFileDesc *fd, void *bufp, int32_t amount,
           int flags, PRIntervalTime to)
{
  char *buf = (char *)bufp;
  fprintf(stderr, "%d aLayerRecv\n", PR_IntervalNow());

  assert(PR_GetLayersIdentity(fd) == aIdentity);

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }

  int32_t rv = sdt_GetData(fd);

  // If we got an error here return it;
  if (rv < 0) {
    PRErrorCode errCode = PR_GetError();
    if (errCode != PR_WOULD_BLOCK_ERROR) {
      return rv;
    }
  }

  if (!handle->hOrderedFramesFirst) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  // Making it so complecated because of PR_MSG_PEEK.
  struct hFrame_t *frame = handle->hOrderedFramesFirst;
  uint32_t frameSize = frame->mDataSize;
  uint32_t frameAlreadyRead = frame->mDataRead;
  int32_t read = 0;
  while ((read < amount) && frame) {
    uint8_t *framebuf = (uint8_t*)(frame + 1);
    int32_t toRead = frameSize - frameAlreadyRead;
    toRead = (toRead > (amount - read)) ? (amount - read) : toRead;
    memcpy(buf + read,
           framebuf + frameAlreadyRead,
           toRead);
    read += toRead;
    if (!(flags & PR_MSG_PEEK)) {
      handle->hOrderedFramesFirst->mDataRead += toRead;
    }
    frameAlreadyRead += toRead;
    if (frameAlreadyRead == frameSize) {
      frame = frame->mNext;
      if (frame) {
        frameSize = frame->mDataSize;
        frameAlreadyRead = frame->mDataRead;
      }
      if (!(flags & PR_MSG_PEEK)) {
        struct hFrame_t *done = handle->hOrderedFramesFirst;
        handle->hOrderedFramesFirst = done->mNext;
        if (!handle->hOrderedFramesFirst) {
          handle->hOrderedFramesLast = NULL;
        }
        free(done);
      }
    }
  }

  if (!read) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  return read;
}

int32_t
sdt_GetData(PRFileDesc *fd)
{
  fprintf(stderr, "%d sdt_GetData\n", PR_IntervalNow());

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

  int32_t rv = 0;
  if (!handle->aLayerBufferLen) {
    rv = fd->lower->methods->recv(fd->lower,
                                  handle->aLayerBuffer,
                                  handle->cleartextpayloadsize,
                                  0,
                                  PR_INTERVAL_NO_WAIT);

    if (rv < 0) {
      return rv;
    }
    handle->aLayerBufferLen = rv;
  }

  handle->numOfRTORetrans = 0;

  sdt2h2(handle);

  if (handle->aNeedAck) {
    struct aPacket_t *pkt = MakeAckPkt(handle);
    unsigned char *buf = (unsigned char *)(pkt + 1);
    int rv = fd->lower->methods->write(fd->lower,
                                       buf,
                                       pkt->mSize);
    free(pkt);
    if (rv < 0) {
      return rv;
    }
    handle->aNeedAck = 0;
  }

  return 0;
}

// Returns header length for data and header frames and
// frame length for others (This include sdt header and all mandatory fields).
static uint16_t
hSDTFrameOrHeaderLen(uint8_t type, uint8_t flags)
{
  uint16_t minLen = 0;
  switch (type) {
    case HTTP2_FRAME_TYPE_DATA:
      minLen  = 1 + 4 + 8 + 2;
      break;
    case HTTP2_FRAME_TYPE_HEADERS:
    case HTTP2_FRAME_TYPE_CONTINUATION:
      minLen  = 1 + 4 + 8 + 2 + 9;
      if (flags & HTTP2_FRAME_FLAG_PRIORITY) {
        minLen  += 4 + 1;
      }
      break;
    case HTTP2_FRAME_TYPE_PRIORITY:
      minLen = 4 + 1;
      break;
    case HTTP2_FRAME_TYPE_RST_STREAM:
      minLen = 1 + 4 + 8 + 4;
      break;
    case HTTP2_FRAME_TYPE_SETTINGS:
      minLen = 0;
      break;
    case HTTP2_FRAME_TYPE_PUSH_PROMISE:
      minLen = 0;
      break;
    case HTTP2_FRAME_TYPE_PING:
      minLen = 1;
    case HTTP2_FRAME_TYPE_GOAWAY:
      minLen = 1 + 4 + 4;
    case HTTP2_FRAME_TYPE_WINDOW_UPDATE:
      minLen = 1 + 4 + 8;
    case HTTP2_FRAME_TYPE_ALTSVC:
    case HTTP2_FRAME_TYPE_LAST:
      minLen = 0;
  }
  return minLen;
}

static void
h22sdt(struct sdt_t *handle, struct aPacket_t *pkt, const unsigned char *buf,
       int32_t amount, uint32_t *read)
{
  LogBuffer("h22std ", buf, amount);

  uint8_t done = 0;
  unsigned char *pktbuf = (unsigned char *)(pkt + 1);
  *read = 0;
  pkt->mSize = 0;

  if (!handle->hMagicHello) {
    // 24 + 4
    if (amount < 28) {
      done = 1;
    } else {
      if (memcmp(buf, magicHello, 24)) {
        assert(0);
      }
      handle->hMagicHello = 1;
      *read = 24;
      // check if next frame is setting, it must be!
      assert(((uint8_t*)buf)[*read + 3] == HTTP2_FRAME_TYPE_SETTINGS);
      // ignore but sinulate a SETTING frame
      hMakeSettingsSettingsAckFrame(handle, 0);
      handle->hSettingRecv = 1;
    }
  }

  while (!done && ((pkt->mSize < handle->cleartextpayloadsize) ||
                   (handle->hState == SDT_H2S_PADDING))) {

    switch (handle->hState) {
      case SDT_H2S_NEWFRAME:
      {
        // If we do not have the whole http2 header, we cannot do much.
        if ((amount - *read) < HTTP2_HEADERLEN) {
          done = 1;
          continue;
        }

        handle->hType = ((uint8_t*)buf)[*read + 3];
        handle->hFlags = ((uint8_t*)buf)[*read + 3 + 1];

        // Check if we have place for a sdt frame in the out going buffer.
        if (hSDTFrameOrHeaderLen(handle->hType, handle->hFlags) >
            (handle->cleartextpayloadsize - pkt->mSize)) {
          done = 1;
          continue;
        }
        memcpy(&handle->hDataLen, buf + *read + 1, 2);
        handle->hDataLen = ntohs(handle->hDataLen);
        handle->hFlags = ((uint8_t*)buf)[*read + 3 + 1];
        handle->hPadding = 0;
        uint16_t len;
        if ((handle->hType == HTTP2_FRAME_TYPE_DATA) ||
            (handle->hType == HTTP2_FRAME_TYPE_HEADERS) ||
            (handle->hType == HTTP2_FRAME_TYPE_CONTINUATION)) {

          //Padding length.
          if (handle->hFlags & 0x08) {
            if ((amount - *read) < (HTTP2_HEADERLEN + 1)) {
              done = 1;
              continue;
            }
            handle->hPadding = ((uint8_t*)buf)[*read + HTTP2_HEADERLEN];
            // fix data length.
            handle->hDataLen -= 1;
            handle->hDataLen -= handle->hPadding;
          }
          len = handle->cleartextpayloadsize - pkt->mSize -
                hSDTFrameOrHeaderLen(handle->hType, 0);
          len = (len > (handle->hDataLen)) ?
                 (handle->hDataLen) : len;
        } else {
          len = handle->hDataLen;
        }

        // Maybe optimize this.
        if ((amount - *read) < (len + HTTP2_HEADERLEN +
                              ((handle->hPadding) ? 1 : 0))) {
          done = 1;
          continue;
        }

        uint32_t http2StreamId;
        memcpy(&http2StreamId, buf + *read + 3 + 1 + 1, 4);
        http2StreamId = ntohl(http2StreamId);
        *read += HTTP2_HEADERLEN;
        *read = *read + ((handle->hPadding) ? 1 : 0);

        // Find stream info.
        handle->hCurrentStream = hFindOutgoingStream(handle, http2StreamId);

        // SDT id. Number 1 and 3 are reserved.
        handle->hSDTStreamId = http2StreamId;
        if (http2StreamId % 2) {
          handle->hSDTStreamId += 4;
        }

        handle->hSDTStreamId = htonl(handle->hSDTStreamId);

        switch (handle->hType) {
          case HTTP2_FRAME_TYPE_DATA:
          case HTTP2_FRAME_TYPE_HEADERS:  // header/continuation frames are not documented good.
          case HTTP2_FRAME_TYPE_CONTINUATION:
          {
            fprintf(stderr, "HTTP2_FRAME_TYPE_DATA or HEADERS or "
                            "CONTINUATION\n");
            handle->hState = SDT_H2S_FILLFRAME;
            break;
          }

          case HTTP2_FRAME_TYPE_PRIORITY:
            fprintf(stderr, "HTTP2_FRAME_TYPE_PRIORITY\n");
            // Priority is not described readly.
            pktbuf[pkt->mSize] = SDT_FRAME_TYPE_PRIORITY;
            pkt->mSize += 1;
            memcpy(pktbuf + pkt->mSize, &handle->hSDTStreamId, 4);
            pkt->mSize += 4;
            memcpy(pktbuf + pkt->mSize, buf + *read, 5);
            *read += 5;
            pkt->mSize += 5;
            break;

          case HTTP2_FRAME_TYPE_RST_STREAM:
          {
            fprintf(stderr, "HTTP2_FRAME_TYPE_RST_STREAM\n");
            pktbuf[pkt->mSize] = SDT_FRAME_TYPE_RST_STREAM;
            pkt->mSize += 1;
            memcpy(pktbuf + pkt->mSize, &handle->hSDTStreamId, 4);
            pkt->mSize += 4;
            uint64_t offset = htonll(handle->hCurrentStream->mNextOffset);
            memcpy(pktbuf + pkt->mSize, &offset, 8);
            pkt->mSize += 8;
            memcpy(pktbuf + pkt->mSize, buf + *read, 4);
            pkt->mSize += 4;
            *read += len;
            break;
          }

          case HTTP2_FRAME_TYPE_SETTINGS:
            {
              fprintf(stderr, "HTTP2_FRAME_TYPE_SETTINGS\n");
              if (handle->hFlags & HTTP2_FRAME_FLAG_ACK) {
                // ignore ack.
              } else {
                // ignore but make a SETTING ACK frame
                hMakeSettingsSettingsAckFrame(handle, 1);
                handle->hSettingRecv = 1;
              }
              *read += len;
            }
            break;
          case HTTP2_FRAME_TYPE_PUSH_PROMISE:
            fprintf(stderr, "HTTP2_FRAME_TYPE_PUSH_PROMISE\n");
            assert(0);

          case HTTP2_FRAME_TYPE_PING:
            fprintf(stderr, "HTTP2_FRAME_TYPE_PING\n");
            if (!(handle->hFlags & HTTP2_FRAME_FLAG_ACK)) {
              pktbuf[pkt->mSize] = SDT_FRAME_TYPE_PING;
              pkt->mSize += 1;
              pkt->mIsPingPkt = 1;
            }
            *read += 8;
            break;

          case HTTP2_FRAME_TYPE_GOAWAY:
            fprintf(stderr, "HTTP2_FRAME_TYPE_GOAWAY\n");
            pktbuf[pkt->mSize] = SDT_FRAME_TYPE_GOAWAY;
            pkt->mSize += 1;
            memcpy(pktbuf + pkt->mSize, buf + *read + 4, 4);
            pkt->mSize += 4;
            uint32_t sdtId;
            memcpy(&sdtId, buf + *read, 4);
            sdtId = ntohl(sdtId);
            // SDT id. Number 1 and 3 are reserved.
            if (sdtId % 2) {
              sdtId += 4;
            }
            sdtId = htonl(sdtId + 2);

            memcpy(pktbuf + pkt->mSize, &sdtId, 4);
            pkt->mSize += 4;
            memset(pktbuf + pkt->mSize, 0, 2);
            pkt->mSize += 2;
            *read += len;
            break;

          case HTTP2_FRAME_TYPE_WINDOW_UPDATE:
            fprintf(stderr, "HTTP2_FRAME_TYPE_WINDOW_UPDATE\n");
            pktbuf[pkt->mSize] = SDT_FRAME_TYPE_WINDOW_UPDATE;
            pkt->mSize += 1;
            memcpy(pktbuf + pkt->mSize, &handle->hSDTStreamId, 4);
            pkt->mSize += 4;
            uint32_t increase;
            memcpy(&increase, buf + *read, 4);
            *read += 4;
            increase = ntohl(increase);
            struct hStream_t* stream = hFindStream(handle, http2StreamId);
            stream->mWindowSize += increase;
            uint64_t offset;
            offset = stream->mWindowSize;
            offset = htonll(offset);
            memcpy(pktbuf + pkt->mSize, &offset, 8);
            pkt->mSize += 8;
            break;

          case HTTP2_FRAME_TYPE_ALTSVC:
            fprintf(stderr, "HTTP2_FRAME_TYPE_ALTSVC\n");
            *read += len;
            break;

          case HTTP2_FRAME_TYPE_LAST:
            fprintf(stderr, "HTTP2_FRAME_TYPE_LAST\n");
            *read += len;
            break;

        }
        break;
      }
      case SDT_H2S_FILLFRAME:
      {
        fprintf(stderr, "SDT_H2S_FILLFRAME\n");
        assert((handle->hType == HTTP2_FRAME_TYPE_DATA) ||
               (handle->hType == HTTP2_FRAME_TYPE_HEADERS) ||
               (handle->hType == HTTP2_FRAME_TYPE_CONTINUATION));

        uint16_t toRead;
        toRead = handle->cleartextpayloadsize - pkt->mSize -
                 hSDTFrameOrHeaderLen(HTTP2_FRAME_TYPE_DATA, 0);
        if (handle->hType != HTTP2_FRAME_TYPE_DATA) {
          toRead -= HTTP2_HEADERLEN;
        }

        toRead = (toRead > handle->hDataLen) ? handle->hDataLen : toRead;

        // Maybe optimize this.
        if ((amount - *read) < toRead) {
          done = 1;
          continue;
        }

        pktbuf[pkt->mSize] = SDT_FRAME_TYPE_STREAM2;

        if (handle->hType == HTTP2_FRAME_TYPE_DATA) {
          if ((handle->hFlags & HTTP2_FRAME_FLAG_END_STREAM) &&
              (handle->hDataLen == toRead)) {
            pktbuf[pkt->mSize] |= SDT_FIN_BIT;
          }
        }
        pkt->mSize += 1;

        if (handle->hType == HTTP2_FRAME_TYPE_DATA) {
          memcpy(pktbuf + pkt->mSize, &handle->hSDTStreamId, 4);
        } else {
          uint32_t id = htonl(3);
          memcpy(pktbuf + pkt->mSize, &id, 4);
        }
        pkt->mSize += 4;

        uint64_t offset;
        if (handle->hType == HTTP2_FRAME_TYPE_DATA) {
          offset = htonll(handle->hCurrentStream->mNextOffset);
        } else {
          offset = htonll(handle->hOutgoingHeaders->mNextOffset);
        }
        memcpy(pktbuf + pkt->mSize, &offset, 8);
        pkt->mSize += 8;

        uint16_t len = toRead;
        if (handle->hType != HTTP2_FRAME_TYPE_DATA) {
          len += HTTP2_HEADERLEN;
        }

        if (handle->hType == HTTP2_FRAME_TYPE_DATA) {
          handle->hCurrentStream->mNextOffset += len;
        } else {
          handle->hOutgoingHeaders->mNextOffset += len;
        }
        handle->hOffsetAll += len; // Needed for WINDOW_UPDATE.

        len = htons(len);
        memcpy(pktbuf + pkt->mSize, &len, 2);
        pkt->mSize += 2;

        if (handle->hType != HTTP2_FRAME_TYPE_DATA) {
          // I am not sure about this, I understood it like this.
          pktbuf[pkt->mSize] = 0;
          pkt->mSize += 1;
          len = toRead;
          len = htons(len);
          memcpy(pktbuf + pkt->mSize, &len, 2);
          pkt->mSize += 2;
          pktbuf[pkt->mSize] = handle->hType;
          pkt->mSize += 1;
          pktbuf[pkt->mSize] = handle->hFlags & HTTP2_FRAME_FLAG_PRIORITY;
          handle->hFlags &= ~HTTP2_FRAME_FLAG_PRIORITY; // only on the first one.
          handle->hType = HTTP2_FRAME_TYPE_CONTINUATION; // The next one must be HTTP2_FRAME_TYPE_CONTINUATION.
          if (handle->hDataLen == toRead) {
            pktbuf[pkt->mSize] |= (handle->hFlags & (HTTP2_FRAME_FLAG_END_STREAM |
                                                     HTTP2_FRAME_FLAG_END_HEADERS));
          }
          pkt->mSize += 1;
          memcpy(pktbuf + pkt->mSize, &handle->hSDTStreamId, 4);
          pkt->mSize += 4;
        }

        memcpy(pktbuf + pkt->mSize, buf + *read, toRead);
        pkt->mSize += toRead;
        *read += toRead;
        assert(handle->hDataLen >= toRead);
        handle->hDataLen -= toRead;

        if (!handle->hDataLen) {
          if (handle->hPadding) {
            handle->hState = SDT_H2S_PADDING;
          } else {
            handle->hState = SDT_H2S_NEWFRAME;
          }
        }
        break;
      }
      case SDT_H2S_PADDING:
      {
        fprintf(stderr, "SDT_H2S_PADDING\n");
        assert((handle->hType == HTTP2_FRAME_TYPE_DATA) ||
               (handle->hType == HTTP2_FRAME_TYPE_HEADERS) ||
               (handle->hType == HTTP2_FRAME_TYPE_CONTINUATION));
        uint32_t len = ((amount - *read) > handle->hPadding) ?
                       handle->hPadding : (amount - *read);
        *read += len;
        assert(handle->hPadding >= len);
        handle->hPadding -= len;
        if (!handle->hPadding) {
          handle->hState = SDT_H2S_NEWFRAME;
        }
        break;
      }
      default:
        assert(0);
    }
  }

  LogBuffer("h22sdt buffer ", pktbuf, pkt->mSize);
}

static int32_t
aLayerWrite(PRFileDesc *fd, const void *buf, int32_t amount)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

  fprintf(stderr, "%d aLayerWrite state=%d amount=%d [%p]\n", PR_IntervalNow(),
          handle->state, amount, (void *)handle);
  fprintf(stderr, "%d aLayerWrite aTransmissionQueue= %d "
          "aRetransmissionQueue=%d mMaxBufferedPkt=%d\n",
          PR_IntervalNow(), handle->aTransmissionQueue.mLen,
          handle->aRetransmissionQueue.mLen, handle->mMaxBufferedPkt);

  switch (handle->state) {
  case SDT_CONNECTING:
    {
      // DTLS have not finish yet, we need to push it forward.
      int rv = fd->lower->methods->write(fd->lower,
                                          NULL,
                                          0);

      if (rv == 0) {
        handle->state = SDT_TRANSFERRING;
        if (amount > 0) {
          PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
          rv = -1;
        }
      } else {
        PRErrorCode errCode = PR_GetError();
        if (errCode != PR_WOULD_BLOCK_ERROR) {
          handle->state = SDT_CLOSING;
        }
      }
      return rv;
    }
  case SDT_TRANSFERRING:
    {

      fprintf(stderr, "aLayerWrite state=SDT_TRANSFERRING queued=%d max=%d\n",
              handle->aTransmissionQueue.mLen +
              handle->aRetransmissionQueue.mLen,
              handle->mMaxBufferedPkt );
      uint32_t dataRead = 0;

      // 1) Accept new data if there is space
      if (amount && ((handle->aTransmissionQueue.mLen +
           handle->aRetransmissionQueue.mLen) < handle->mMaxBufferedPkt)) {

        PR_STATIC_ASSERT((handle->cleartextpayloadsize) <= SDT_MTU);

        struct aPacket_t *pkt =
          (struct aPacket_t *) malloc (sizeof(struct aPacket_t) +
                                       handle->cleartextpayloadsize);

        pkt->mIdsNum = 0;
        pkt->mForRetransmission = 0;
        pkt->mSize = 0;
        pkt->mIsPingPkt = 0;

        h22sdt(handle, pkt, buf, amount, &dataRead);
        unsigned char *pktbuf = (unsigned char *)(pkt + 1);
        LogBuffer("h22sdt buffer ", pktbuf, pkt->mSize);
        fprintf(stderr, "aLayerWrite: data read %d written %d\n",
                dataRead, pkt->mSize);
        if (pkt->mSize > 0) {
          PacketQueueAddNew(&handle->aTransmissionQueue, pkt);
        } else {
          free (pkt);
        }
      }

      // 2) Check if a timer expired
      CheckRetransmissionTimers(handle);
      if (handle->numOfRTORetrans > aMaxNumOfRTORetrans) {
        PR_SetError(PR_IO_TIMEOUT_ERROR, 0);
        return -1;
      }

      // 3) Send a packet.
      // Because of the congestion control we need to send as much as we can.
      // (SocketTransport we call read, then write then read... on the socket.
      //  If ack arrives and increases cwnd, write must be call more than once
      //  to send as mach as we can. If we do not do that, if we call it just
      //  once bytes_in_fligts will be less than cwnd and on the next ack cc is
      //  app limited.)
      if (RetransmitQueued(handle)) {
        handle->aPktTransmit = handle->aRetransmissionQueue.mFirst;
      } else {
        handle->aPktTransmit = handle->aTransmissionQueue.mFirst;
      }
      int32_t rv = 0;

      while ((rv > -1) && handle->aPktTransmit) {
        unsigned char *pktbuf = (unsigned char *)(handle->aPktTransmit + 1);
//LogBuffer("aLayerSendTo pkt ", buf, amount + sizeof(struct aPacket_t));
        rv = fd->lower->methods->write(fd->lower,
                                       pktbuf,
                                       handle->aPktTransmit->mSize);
        if (rv < 0) {
          handle->aPktTransmit = NULL;
          PRErrorCode errCode = PR_GetError();
          if (errCode != PR_WOULD_BLOCK_ERROR) {
            return rv;
          }
        } else {
          // Start rto timer if needed. RTO timere is started only for data
          // packets.
          MaybeStartRTOTimer(handle);

          fprintf(stderr, "LayerSendTo amount=%d newDataRead=%d pkt_sz=%d "
                  "rv=%d pkt=%p number_of_ids=%d\n",
                  amount, dataRead, handle->aPktTransmit->mSize, rv,
                  (void *)handle->aPktTransmit, handle->aPktTransmit->mIdsNum);

//        buf = (unsigned char *)(handle->aPktTransmit);
//        LogBuffer("aLayerSendTo pkt 2", buf,
//                  handle->aPktTransmit->mSize + sizeof(struct aPacket_t));

          if (!handle->aPktTransmit->mForRetransmission) {
            PacketQueueRemoveFirstPkt(&handle->aTransmissionQueue);
          } else {
            PacketQueueRemoveFirstPkt(&handle->aRetransmissionQueue);
            handle->aPktTransmit->mForRetransmission = 0;
          }
          PacketQueueAddNew(&handle->aRetransmissionQueue, handle->aPktTransmit);

          if (RetransmitQueued(handle)) {
            handle->aPktTransmit = handle->aRetransmissionQueue.mFirst;
          } else {
            handle->aPktTransmit = handle->aTransmissionQueue.mFirst;
          }
        }
      }

      // 4) Send an ack if necessary.
      if (DoWeNeedToSendAck(handle)) {
        struct aPacket_t *pkt = MakeAckPkt(handle);
        unsigned char *buf = (unsigned char *)(pkt + 1);
        int rv = fd->lower->methods->write(fd->lower,
                                           buf,
                                           pkt->mSize);
        free(pkt);

        if (rv < 0) {
          PRErrorCode errCode = PR_GetError();
          if (errCode != PR_WOULD_BLOCK_ERROR) {
            return rv;
          }
        }
      }
      if (dataRead) {
        return dataRead;
      } else {
        PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
        return -1;
      }
    }
  case SDT_CLOSING:
    // TODO CLOSING part!!!
    assert (0);
  }

  return -1;
}

int
qAllowSend(struct sdt_t *handle)
{
  // first update credits
  if (handle->qCredits < handle->qMaxCredits) {
    PRTime now = PR_Now();
    PRTime delta = now - handle->qLastCredit;
    handle->qCredits += delta;
    handle->qLastCredit = now;
    if (handle->qCredits > handle->qMaxCredits) {
      handle->qCredits = handle->qMaxCredits;
    }
  }
  return (handle->qCredits >= handle->qPacingRate);
}

void
qChargeSend(struct sdt_t *handle)
{
  if (handle->qCredits < handle->qPacingRate) {
    DEV_ABORT(0);
    handle->qCredits = 0;
    return;
  }

  handle->qCredits -= handle->qPacingRate;
}

static int32_t
qLayerRecv(PRFileDesc *fd, void *buf, int32_t amount,
           int flags, PRIntervalTime to)
{
  return fd->lower->methods->recv(fd->lower, buf, amount, flags, to);
}

static int32_t
qLayerWrite(PRFileDesc *fd, const void *buf, int32_t amount)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

/*  if (!qAllowSend(handle)) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
*/
  // send now
//  qChargeSend(handle);

  // If we can send according to cwnd, this is an ack, a retransmission or
  // we are writnig 0 bytes.
  int32_t rv = -1;
  if (cc->CanSend(handle) || !handle->aPktTransmit || !amount) {
    rv = fd->lower->methods->write(fd->lower, buf, amount);
    if ((rv > 0) && handle->aPktTransmit) {
      cc->OnPacketSent(handle, handle->aPktTransmit->mIds[handle->aPktTransmit->mIdsNum - 1].mSeq,
                       handle->aPktTransmit->mSize + DTLS_PART + handle->publicHeader);
    }
    return rv;
  } else {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
  }
  return rv;
}

static PRStatus
sLayerConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return PR_FAILURE;
  }
  char host[164] = {0};
  PR_NetAddrToString(addr, host, sizeof(host));
  fprintf(stderr, "sLayerConnect host: %s\n", host);
  int port = 0;
  if (addr->raw.family == AF_INET) {
    port = addr->inet.port;
  } else if (addr->raw.family == AF_INET6) {
    port = addr->ipv6.port;
  }
  fprintf(stderr, "sLayerConnect port: %d\n", ntohs(port));

  memcpy(&(handle->peer), addr, sizeof(PRNetAddr));

  if (addr->raw.family == AF_INET6) {
    handle->payloadsize -= SDT_PAYLOADSIZE_DIFF;
    handle->cleartextpayloadsize -= SDT_PAYLOADSIZE_DIFF;
  }
  handle->isConnected = 1;
  return PR_SUCCESS;
}

static PRStatus
sLayerBind(PRFileDesc *fd, const PRNetAddr *addr)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return PR_FAILURE;
  }

  return fd->lower->methods->bind(fd->lower, addr);
}

static PRStatus
sLayerGetSockName(PRFileDesc *fd, PRNetAddr *addr)
{
  return fd->lower->methods->getsockname(fd->lower, addr);
}

static PRStatus
sLayerGetPeerName(PRFileDesc *fd, PRNetAddr *addr)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle || !handle->isConnected) {
    return PR_FAILURE;
  }

  memcpy(addr, &handle->peer, sizeof (PRNetAddr));
  return PR_SUCCESS;
}

static PRStatus
sLayerGetSocketOption(PRFileDesc *fd, PRSocketOptionData *opt)
{
  return fd->lower->methods->getsocketoption(fd->lower, opt);
}

static PRStatus
sLayerSetSocketOption(PRFileDesc *fd, const PRSocketOptionData *opt)
{
  return fd->lower->methods->setsocketoption(fd->lower, opt);
}

static PRInt16 PR_CALLBACK
sLayerPoll(PRFileDesc *fd, PRInt16 how_flags, PRInt16 *p_out_flags)
{
  assert(fd->lower->methods->poll);
  return fd->lower->methods->poll(fd->lower, how_flags, p_out_flags);
}

static PRInt16 PR_CALLBACK
qLayerPoll(PRFileDesc *fd, PRInt16 how_flags, PRInt16 *p_out_flags)
{
  *p_out_flags = 0;
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return PR_POLL_ERR;
  }

  if (handle->state == SDT_TRANSFERRING) {
    if ((how_flags & PR_POLL_WRITE) &&
        !(cc->CanSend(handle) ||
          DoWeNeedToSendAck(handle))) { //&& !qAllowSend(handle)) {
      how_flags^= PR_POLL_WRITE;
    }
  }

  assert(fd->lower->methods->poll);
  return fd->lower->methods->poll(fd->lower, how_flags, p_out_flags);
}

static PRInt16 PR_CALLBACK
aLayerPoll(PRFileDesc *fd, PRInt16 how_flags, PRInt16 *p_out_flags)
{
  *p_out_flags = 0;

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    *p_out_flags = PR_POLL_ERR;
    return how_flags;
  }

  if (handle->state == SDT_TRANSFERRING) {
    if ((how_flags & PR_POLL_WRITE) &&
        !(NeedToSendRetransmit(handle) ||
          handle->aTransmissionQueue.mLen ||
          DoWeNeedToSendAck(handle))) {

      how_flags ^= PR_POLL_WRITE;
    }

    if (how_flags & PR_POLL_READ) {
      if (handle->aLayerBufferLen) {
        *p_out_flags |= PR_POLL_READ;
        return how_flags;
      }
    }
  }

  assert(fd->lower->methods->poll);
  return fd->lower->methods->poll(fd->lower,
                                  how_flags,
                                  p_out_flags);
}

static void
strongDtor(PRFileDesc *fd)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (handle) {
    fd->secret = NULL;
    sdt_freeHandle(handle);
  }
  PR_DELETE(fd);
}

uint8_t
sdt_HasData(PRFileDesc *fd)
{
  assert(PR_GetLayersIdentity(fd) == aIdentity);
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }

  return (handle->hOrderedFramesFirst != 0);
}

uint8_t
sdt_SocketWritable(PRFileDesc * fd)
{
  assert(PR_GetLayersIdentity(fd) == aIdentity);
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }

  return ((handle->aTransmissionQueue.mLen + handle->aRetransmissionQueue.mLen)
          < handle->mMaxBufferedPkt);
}

static int sdt_once = 0;
void
sdt_ensureInit()
{
  if (sdt_once) {
    return;
  }
  sdt_once = 1;

  sMinRTO = PR_MillisecondsToInterval(MIN_RTO); // 1s
  sMaxRTO = PR_MillisecondsToInterval(MAX_RTO); // 60s

  qIdentity = PR_GetUniqueIdentity("sdt-qLayer");
  sIdentity = PR_GetUniqueIdentity("sdt-sLayer");
  aIdentity = PR_GetUniqueIdentity("sdt-aLayer");

  qMethods = *PR_GetDefaultIOMethods();
  sMethods = *PR_GetDefaultIOMethods();
  aMethods = *PR_GetDefaultIOMethods();

  // setup read side methods
  // qLayer is nop
  sMethods.read = sdt_useRecv;
  sMethods.recv = sLayerRecv;
  sMethods.recvfrom = sdt_notImplemented;
  // cLayer is nss
  sMethods.write = useSendTo1;
  sMethods.send = useSendTo2;
  sMethods.sendto = sLayerSendTo;

  qMethods.read = sdt_useRecv;
  qMethods.recv = qLayerRecv;
  qMethods.recvfrom = sdt_notImplemented;
  qMethods.write = qLayerWrite;
  qMethods.send = sdt_notImplemented2;
  qMethods.sendto = sdt_notImplemented3;

  aMethods.read = sdt_useRecv;
  aMethods.recv = aLayerRecv;
  aMethods.recvfrom = sdt_notImplemented;
  aMethods.write = aLayerWrite;
  aMethods.send = sdt_notImplemented2;
  aMethods.sendto = sdt_notImplemented3;

  // some other general methods
  sMethods.connect = sLayerConnect;
//  qMethods.connect = sLayerConnect;
  sMethods.bind = sLayerBind;
  sMethods.getsockname = sLayerGetSockName;
  sMethods.getpeername = sLayerGetPeerName;
  sMethods.getsocketoption = sLayerGetSocketOption;
  sMethods.setsocketoption = sLayerSetSocketOption;
  sMethods.poll = sLayerPoll;
  qMethods.poll = qLayerPoll;
  aMethods.poll = aLayerPoll;
  qMethods.close = genericClose;
  sMethods.close = genericClose;
  aMethods.close = genericClose;

  cc = &tcp_general;
}

PRFileDesc *
sdt_openSocket(PRIntn af)
{
  sdt_ensureInit();

  PRFileDesc *fd = PR_OpenUDPSocket(af);

  PRSocketOptionData opt;
  opt.option = PR_SockOpt_Nonblocking;
  opt.value.non_blocking =  1;
  PR_SetSocketOption(fd, &opt);

  return sdt_addSDTLayers(fd);
}

PRFileDesc *
sdt_addSDTLayers(PRFileDesc *fd)
{
  PRFileDesc *sLayer = NULL;

  sLayer = PR_CreateIOLayerStub(sIdentity, &sMethods);

  if (!(fd && sLayer)) {
    goto fail; // ha!
  }

  sLayer->dtor = strongDtor;

  struct sdt_t *handle = sdt_newHandle();
  if (!handle) {
    goto fail;
  }
  sLayer->secret = (struct PRFilePrivate *)handle;

  if (PR_PushIOLayer(fd, PR_GetLayersIdentity(fd), sLayer) == PR_SUCCESS) {
    sLayer = NULL;
  } else {
    goto fail;
  }

  handle->fd = fd;
  return fd;

fail:
  PR_Close(fd);
  if (sLayer) {
    sLayer->dtor(sLayer);
  }
  return NULL;
}

PRFileDesc *
sdt_addALayer(PRFileDesc *fd)
{
  PRFileDesc * sFd = PR_GetIdentitiesLayer(fd, sIdentity);
  struct sdt_t *handle = (struct sdt_t *)(sFd->secret);

  if (!handle) {
    goto fail;
  }

  PRFileDesc *qLayer = NULL;
  PRFileDesc *aLayer = NULL;

  qLayer = PR_CreateIOLayerStub(qIdentity, &qMethods);
  aLayer = PR_CreateIOLayerStub(aIdentity, &aMethods);

  if (!(fd && qLayer && aLayer)) {
    goto fail; // ha!
  }

  qLayer->dtor = weakDtor;
  aLayer->dtor = weakDtor;

  qLayer->secret = (struct PRFilePrivate *)handle;
  aLayer->secret = (struct PRFilePrivate *)handle;

  if (PR_PushIOLayer(fd, PR_GetLayersIdentity(fd), qLayer) == PR_SUCCESS) {
    qLayer = NULL;
  } else {
    goto fail;
  }

  if (PR_PushIOLayer(fd, PR_GetLayersIdentity(fd), aLayer) == PR_SUCCESS) {
    aLayer = NULL;
  } else {
    goto fail;
  }

  handle->fd = fd;
  return fd;

fail:
  PR_Close(fd);
  if (qLayer) {
    qLayer->dtor(qLayer);
  }
  if (aLayer) {
    aLayer->dtor(aLayer);
  }
  return NULL;
}
