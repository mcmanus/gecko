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

#include "sdt_common.h"
#include "congestion_control.h"
#include "tcp_general.h"

// H2 mapping will move to a separate layer but for now I want to separate 2
// versions. So Firefox side needs H2MAPPING unset and proxy side needs it set.
#define H2MAPPING 1

// TODO connection reusing
// TODO lots of compile warnings

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

#define HTTP2_TRANSFORMAION 1

#define DEFAULTE_WINDOW_SIZE (2 << 16) - 1
#define DEFAULTE_RWIN 65535
// max amout of outstanding data (sender buffer). (1048576*1400)
static uint64_t aBufferLenMax = 1468006400;

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
#define HTTP2_FRAME_FLAG_PADDED        0x08
#define HTTP2_FRAME_FLAG_PRIORITY      0x20
#define HTTP2_FRAME_FLAG_ACK           0x01

#define HTTP2_SETTINGS_TYPE_HEADER_TABLE_SIZE 0x01
#define HTTP2_SETTINGS_ENABLE_PUSH            0x02
#define HTTP2_SETTINGS_TYPE_MAX_CONCURRENT    0x03
#define HTTP2_SETTINGS_TYPE_INITIAL_WINDOW    0x04
#define HTTP2_SETTINGS_MAX_FRAME_SIZE         0x05

#define HTTP2_HEADERLEN                9

#define SDT_FRAME_TYPE_STREAM              0x80
#define SDT_FRAME_TYPE_ACK                 0x40
#define SDT_FRAME_TYPE_CONGESTION_FEEDBACK 0x20
#define SDT_FRAME_TYPE_PADDING             0x00
#define SDT_FRAME_TYPE_RST_STREAM          0x01
#define SDT_FRAME_TYPE_CONNECTION_CLOSE    0x02
#define SDT_FRAME_TYPE_GOAWAY              0x03
#define SDT_FRAME_TYPE_WINDOW_UPDATE       0x04
#define SDT_FRAME_TYPE_BLOCKED             0x05
#define SDT_FRAME_TYPE_PING                0x07
#define SDT_FRAME_TYPE_PRIORITY            0x08

// 1(frame type) + 2(length) + 4(stream) + 8(offset)
#define SDT_FRAME_TYPE_STREAM_HEADER_SIZE 15
#define SDT_FRAME_STREAM_FIN_BIT 0x40
#define SDT_FRAME_STREAM_DATA_LENGTH_BIT 0x20

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

// max amout of outstanding data (sender buffer). (1048576*1400)
//static uint64_t aBufferLenMax = 1468006400;

// our standard time unit is a microsecond
static uint64_t qMaxCreditsDefault = 80000; // ums worth of full bucket
static uint64_t qPacingRateDefault =  5000; // send every 2ms (2000ums)

static uint8_t aMaxNumOfRTORetrans = 6;

#define DUPACK_THRESH 3
#define EARLY_RETRANSMIT_FACTOR 0.25

#define NUMBER_OF_TIMESTAMPS_STORED 8

#define MAX_RTO 60000 // 60s
#define MIN_RTO 1000 // 1s

static PRIntervalTime sMinRTO; // MinRTO in interval that we do not need to convert it each time.
static PRIntervalTime sMaxRTO; // MaxRTO in interval that we do not need to convert it each time.

#define RTO_FACTOR 4
#define RTT_FACTOR_ALPHA 0.125
#define RTT_FACTOR_BETA 0.25

static struct sdt_congestion_control_ops *cc;// = sdt_cc;

//static uint32_t amplificationPacket = 2;

//------------------------------------------------------------------------------
// DECODE and ENCODE frames !!!! START
//------------------------------------------------------------------------------

uint8_t
sdt_decode_OffsetLength(uint8_t type)
{
  // 0, 16, 24, 32, 40 ,48, 56, 64
  type = (type >> 2) & 0x07;
  return (type) ? type + 1 : 0;
}

uint8_t
sdt_decode_StreamIdLength(uint8_t type)
{
  // 8, 16, 24, 32
  return ((type & 0x03) + 1);
}

int32_t
sdt_decode_StreamFrame(const uint8_t *buf, uint16_t length,
                       uint32_t *streamId, uint8_t *streamIdLen,
                       uint64_t *offset, uint8_t *offsetLen,
                       uint8_t *fin, uint16_t *frameLen)
{
  uint32_t read = 0;
  assert(length >= 1);

  uint8_t type = buf[0];
  read++;

  if (type & SDT_FRAME_STREAM_FIN_BIT) {
    *fin = 1;
  }

  *streamIdLen = sdt_decode_StreamIdLength(type);
  *offsetLen = sdt_decode_OffsetLength(type);

  if (type & SDT_FRAME_STREAM_DATA_LENGTH_BIT) {
    if (length < (3 + *streamIdLen + *offsetLen)) {
      return SDTE_PROTOCOL_ERROR;
    }
    memcpy(frameLen, buf + read, 2);
    *frameLen = ntohs(*frameLen);
    read += 2;
  } else {
    if (length < (1 + *streamIdLen + *offsetLen)) {
      return SDTE_PROTOCOL_ERROR;
    }
    *frameLen = length - 1 - *offsetLen - *streamIdLen;
  }

  if (!*frameLen && !*fin) {
    return SDTE_PROTOCOL_ERROR;
  }
  if (length < (read + *streamIdLen + *offsetLen + *frameLen)) {
    return SDTE_PROTOCOL_ERROR;
  }

  *streamId = 0;
  switch(*streamIdLen) {
  case 1:
    *streamId = (uint64_t)buf[read];
    break;
  case 2:
  {
    uint16_t id;
    memcpy(&id, buf + read, 2);
    *streamId = ntohs(id);
    break;
  }
  case 3:
  {
    uint16_t id;
    memcpy(&id, buf + read + 1, 2);
    *streamId = ntohs(id);
    *streamId += ((uint64_t)buf[read]) << 16;
  }
  case 4:
  {
    uint32_t id;
    memcpy(&id, buf + read, 4);
    *streamId = ntohl(id);
    break;
  }
  default:
    assert(0);
  }
  read += *streamIdLen;

  switch (*offsetLen) {
  case 0:
    *offset = 0;
    break;
  case 2:
  {
    uint16_t off;
    memcpy(&off, buf + read, 2);
    *offset = ntohs(off);
    break;
  }
  case 3:
  {
    uint16_t off;
    memcpy(&off, buf + read + 1, 2);
    *offset = ntohs(off);
    *offset += ((uint64_t)buf[read]) << 16;
    break;
  }
  case 4:
  {
    uint32_t off;
    memcpy(&off, buf + read, 4);
    *offset = ntohl(off);
    break;
  }
  case 5:
  {
    uint32_t off;
    memcpy(&off, buf + read + 1, 4);
    *offset = ntohl(off);
    *offset += ((uint64_t)buf[read]) << 32;
    break;
  }
  case 6:
  {
    uint32_t off;
    memcpy(&off, buf + read + 2, 4);
    *offset = ntohl(off);
    *offset += ((uint64_t)buf[read + 1]) << 32;
    *offset += ((uint64_t)buf[read]) << 40;
    break;
  }
  case 7:
  {
    uint32_t off;
    memcpy(&off, buf + read + 3, 4);
    *offset = ntohl(off);
    *offset += ((uint64_t)buf[read + 2]) << 32;
    *offset += ((uint64_t)buf[read + 1]) << 40;
    *offset += ((uint64_t)buf[read]) << 48;
    break;
  }
  case 8:
  {
    memcpy(&offset, buf + read, 8);
    *offset = ntohll(*offset);
    break;
  }
  default:
    assert(0);
  }
  read += *offsetLen;

  fprintf(stderr, "sdt_decode_StreamFrame: streamId=%u streamIdLen=%d "
                  "offset=%lu offsetLen=%d fin=%d frameLen=%d read=%d\n",
                  *streamId, *streamIdLen, *offset, *offsetLen, *fin, *frameLen,
                  read);
  return read;
}

int32_t
sdt_encode_StreamFrame(uint8_t *buf,
                       uint32_t streamId, uint8_t streamIdLen,
                       uint64_t offset, uint8_t offsetLen,
                       uint8_t fin, uint8_t addFrameLen, uint16_t frameLen)
{
  fprintf(stderr, "sdt_encode_StramFrame: streamId=%d streamIdLen=%d "
          "offset=%lu offsetLen=%d fin=%d frameLength=%d\n",
          streamId, streamIdLen,
          offset, offsetLen, fin, frameLen);

  buf[0] = SDT_FRAME_TYPE_STREAM;
  if (fin) {
    buf[0] |= SDT_FRAME_STREAM_FIN_BIT;
  }
  if (offsetLen) {
    buf[0] |= (offsetLen - 1) << 2;
  }
  buf[0] |= (streamIdLen - 1);

  int32_t written = 1;

  if (addFrameLen) {
    buf[0] |= SDT_FRAME_STREAM_DATA_LENGTH_BIT;
    frameLen = htons(frameLen);
    memcpy(buf + 1, &frameLen, 2);
    written += 2;
  }

  switch (streamIdLen) {
  case 1:
  {
    uint8_t id = (uint8_t)streamId;
    memcpy(buf + written, &id, 1);
    break;
  }
  case 2:
  {
    uint16_t id;
    id = htons((uint16_t)streamId);
    memcpy(buf + written, &id, 2);
    break;
  }
  case 3:
  {
    uint16_t id = htons((uint16_t)streamId);
    memcpy(buf + written + 1, &id, 2);
    buf[written] = (uint8_t)(streamId >> 16);
  }
  case 4:
  {
    uint32_t id = htonl(streamId);
    memcpy(buf + written, &id, 4);
    break;
  }
  default:
    assert(0);
  }
  written += streamIdLen;

  switch (offsetLen) {
  case 0:
    break;
  case 2:
  {
    uint16_t off = htons((uint16_t)offset);
    memcpy(buf + written, &off, 2);
    break;
  }
  case 3:
  {
    uint16_t off = htons((uint16_t)offset);
    memcpy(buf + written + 1, &off, 2);
    buf[written] = (uint8_t)(offset >> 16);
    break;
  }
  case 4:
  {
    uint32_t off = htonl((uint32_t)offset);
    memcpy(buf + written, &off, 4);
    break;
  }
  case 5:
  {
    uint32_t off = htonl((uint32_t)offset);
    memcpy(buf + written + 1, &off, 4);
    buf[written] = (uint8_t)(offset >> 32);
    break;
  }
  case 6:
  {
    uint32_t off = htonl((uint32_t)offset);
    memcpy(buf + written + 2, &off, 4);
    buf[written + 1] = (uint8_t)(offset >> 32);
    buf[written] = (uint8_t)(offset >> 40);
    break;
  }
  case 7:
  {
    uint32_t off = htonl((uint32_t)offset);
    memcpy(buf + written + 3, &off, 4);
    buf[written + 2] = (uint8_t)(offset >> 32);
    buf[written + 1] = (uint8_t)(offset >> 40);
    buf[written] = (uint8_t)(offset >> 48);
    break;
  }
  case 8:
  {
    offset = htonll(offset);
    memcpy(buf + written, &offset, 8);
    break;
  }
  default:
    assert(0);
  }
  written += offsetLen;
  return written;
}

//------------------------------------------------------------------------------
// DECODE and ENCODE frames !!!! END
//------------------------------------------------------------------------------

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
//  return;
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


struct aPacket_t
{
  uint32_t mSize;
  uint32_t mWritten;
  // the buffer lives at the end of the struct.
};

// FOR TESTING!!!!!
struct aPacket_t *
CreatePacket(uint32_t size)
{
  struct aPacket_t *pkt =
    (struct aPacket_t *) malloc (sizeof(struct aPacket_t) + size);
  if (!pkt) {
    return NULL;
  }
  pkt->mSize = size;
  return pkt;
}

struct range32_t
{
  uint32_t mStart;
  uint32_t mEnd;
  struct range32_t *mNext;
};

static int32_t
AddRange(struct range32_t **rangeList, uint32_t start, uint32_t end)
{
  struct range32_t *rcurr = *rangeList;
  struct range32_t *rprev = NULL;
  while (rcurr && (rcurr->mStart < start)) {
    rprev = rcurr;
    rcurr = rcurr->mNext;
  }

  if ((!rprev || (rprev->mEnd < start)) && (!rcurr || (rcurr->mStart > end))) {
    // Add a new range.
    struct range32_t *r =
      (struct range32_t *) malloc (sizeof(struct range32_t));
    if (!r) {
      return SDTE_OUT_OF_MEMORY;
    }
    r->mStart = start;
    r->mEnd = end;
    r->mNext = rcurr;
    if (rprev) {
      rprev->mNext = r;
    } else {
      *rangeList = r;
    }
  } else {
    if (rprev && rprev->mEnd >= start) {
      if (rprev->mEnd <= end) {
        // Extend rprev.
        rprev->mEnd = end;
      }
    } else if (rcurr) {
      // Extend rcurr
      rcurr->mStart = start;
      if (rcurr->mEnd < end) {
        rcurr->mEnd = end;
      }
      rprev = rcurr;
      rcurr = rcurr->mNext;
    }

    // Check if extended rprev contains some other ranges.
    while (rcurr && rcurr->mStart <= rprev->mEnd) {
      if (rcurr->mEnd > rprev->mEnd) {
        rprev->mEnd = rcurr->mEnd;
      }

      rprev->mNext = rcurr->mNext;
      free(rcurr);
      rcurr = rprev->mNext;
    }
  }
  return 0;
}

static int32_t
RemoveRange(struct range32_t **rangeList, uint32_t start, uint32_t end,
            struct range32_t **removedRanges)
{
  assert(end - start);
  assert(!removedRanges || (*removedRanges == NULL));
  struct range32_t *rcurr = *rangeList;
  struct range32_t *rprev = NULL;
  while (rcurr && (rcurr->mStart < start)) {
    rprev = rcurr;
    rcurr = rcurr->mNext;
  }

  if ((!rprev || (rprev->mEnd <= start)) && (!rcurr || (rcurr->mStart > end))) {
      // Range does not exist!
  } else {

    if (rprev && rprev->mEnd > start) {

      if (rprev->mEnd <= end) {
        // Remove a part of the rprev start.
        if (removedRanges) {
          struct range32_t *r =
            (struct range32_t *) malloc (sizeof(struct range32_t));
          if (!r) {
            return SDTE_OUT_OF_MEMORY;
          }
          r->mStart = start;
          r->mEnd = rprev->mEnd;
          r->mNext = *removedRanges;
          *removedRanges = r;
        }
        rprev->mEnd = start;
      } else {
        // split rprev!
        struct range32_t *r =
          (struct range32_t *) malloc (sizeof(struct range32_t));
        if (!r) {
          return SDTE_OUT_OF_MEMORY;
        }
        r->mStart = end;
        r->mEnd = rprev->mEnd;
        rprev->mEnd = start;
        r->mNext = rprev->mNext;
        rprev->mNext = r;

        if (removedRanges) {
          r = (struct range32_t *) malloc (sizeof(struct range32_t));
          if (!r) {
            return SDTE_OUT_OF_MEMORY;
          }
          r->mStart = start;
          r->mEnd = end;
          r->mNext = *removedRanges;
          *removedRanges = r;
        }
      }
    }

    // Remove from rcurr and check if the next ranges needs to be removed!
    while (rcurr && rcurr->mEnd <= end) {
      struct range32_t *r = rcurr;
      if (rprev) {
        rprev->mNext = rcurr->mNext;
        rcurr = rprev->mNext;
      } else {
        *rangeList = rcurr->mNext;
        rcurr = *rangeList;
      }

      if (removedRanges) {
        r->mNext = *removedRanges;
        *removedRanges = r;
      } else {
        free(r);
      }
    }
    if (rcurr && rcurr->mStart < end) {
      if (removedRanges) {
        struct range32_t *r =
            (struct range32_t *) malloc (sizeof(struct range32_t));
        if (!r) {
          return SDTE_OUT_OF_MEMORY;
        }
        r->mStart = rcurr->mStart;
        r->mEnd = end;
        r->mNext = *removedRanges;
        *removedRanges = r;
      }
      rcurr->mStart = end;
    }
  }
  return 0;
}

enum ChunkType {
  DATA_CHUNK,
  CONTROL_CHUNK
};

// This contains only chunk data and its size.
struct aChunk_t {
  uint32_t mSize;
  uint32_t mWritten;
  // the buffer lives at the end of the struct
};

// Streams are going to save data in chunks as they are arriving from the
// application. For data and header frames a chunk is actually a h2 frame
// without frame header and for control frame is complete sdt control frame.
// A chunk data will be delete as soon as all the data is acked. We need to keep
// track of chunk's parts that are still not send or sent but not acked, i.e.
// mNotSentRanges and mUnackedRanges. When some data is sent the corresponding
// range is moved from mNotSentRanges to mUnackedRanges. When some data are
// lost the corresponding range is moved from mUnackedRanges to mNotSentRanges.
// When some data are acked the corresponding range is removed.
struct aDataChunk_t
{
  uint32_t mRefCnt;
  enum ChunkType mType;
  struct range32_t *mNotSentRanges;
  struct range32_t *mUnackedRanges; // this is a chain of unacked ranges of this
                                    // chunk.
  uint8_t mFin; // The last data chunk for this stream;
  uint64_t mOffset; // offset of the first byte of the chunk.

  uint32_t mStreamId;

  struct aDataChunk_t *mNext;
  struct aChunk_t *mData;
};

struct aDataChunk_t *
CreateChunk(enum ChunkType type, uint32_t size, uint32_t streamId)
{
  struct aDataChunk_t *chunk =
    (struct aDataChunk_t *) calloc (1, sizeof(struct aDataChunk_t));
  if (!chunk) {
    return NULL;
  }

  chunk->mData = (struct aChunk_t *) malloc(sizeof(struct aChunk_t) + size);

  if (!chunk->mData) {
    free(chunk);
    return NULL;
  }
  chunk->mData->mSize = size;
  chunk->mData->mWritten = 0;

  chunk->mType = type;
  chunk->mFin = 0;
  chunk->mStreamId = streamId;

  return chunk;
}

static unsigned char *
GetDataChunkBuf(struct aDataChunk_t *chunk)
{
  assert(chunk);
  assert(chunk->mData);

  struct aChunk_t *data = chunk->mData;

  return (unsigned char *)(data + 1);
}

void
FreeDataChunk(struct aDataChunk_t *chunk)
{
  assert(chunk->mRefCnt);
  chunk->mRefCnt--;

  if (!chunk->mRefCnt) {
    while(chunk->mNotSentRanges) {
      struct range32_t *r = chunk->mNotSentRanges;
      chunk->mNotSentRanges = chunk->mNotSentRanges->mNext;
      free(r);
    }

    while(chunk->mUnackedRanges) {
      struct range32_t *r = chunk->mUnackedRanges;
      chunk->mUnackedRanges = chunk->mUnackedRanges->mNext;
      free(r);
    }

    if (chunk->mData) {
      free(chunk->mData);
    }
  }
}

void
LogRanges(struct aDataChunk_t *chunk)
{
 return;
  assert(chunk);

  struct range32_t *r = chunk->mNotSentRanges;
  fprintf(stdout, "mNotSentRanges for chunk %p:\n", chunk);
  while(r) {
    fprintf(stdout, "Range: %p %d %d\n", r, r->mStart, r->mEnd);
    r = r->mNext;
  }
  fprintf(stdout, "\nmUnackedRanges for chunk %p:\n", chunk);
  r = chunk->mUnackedRanges;
  while(r) {
    fprintf(stdout, "Range: %p %d %d\n", r, r->mStart, r->mEnd);
    r = r->mNext;
  }
  fprintf(stdout, "\nRanges printed!\n");
}

//FOR TESTING!!!!!
int32_t
ChunkRefCnt(struct aDataChunk_t *chunk)
{
  return chunk->mRefCnt;
}

//FOR TESTING!!!!!
void
ChunkAddRef(struct aDataChunk_t *chunk)
{
  chunk->mRefCnt++;
}

// FOR TESTING!!!!
void
AddNewRange(struct aDataChunk_t *chunk, uint32_t start, uint32_t end)
{
  AddRange(&chunk->mNotSentRanges, start, end);
}

// FOR TESTING!!!!
uint32_t
NumNotSentRanges(struct aDataChunk_t *chunk)
{
  uint32_t cnt = 0;
  struct range32_t *r = chunk->mNotSentRanges;
  while(r) {
    cnt++;
    r = r->mNext;
  }
  return cnt;
}

// FOR TESTING!!!!
uint8_t
HasNotSentRange(struct aDataChunk_t *chunk, uint32_t start, uint32_t end)
{
  struct range32_t *r = chunk->mNotSentRanges;
  while(r) {
    if (r->mStart == start && r->mEnd == end) {
      return 1;
    }
    r = r->mNext;
  }
  return 0;
}

// FOR TESTING!!!!
uint32_t
NumUnackedRanges(struct aDataChunk_t *chunk)
{
  uint32_t cnt = 0;
  struct range32_t *r = chunk->mUnackedRanges;
  while(r) {
    cnt++;
    r = r->mNext;
  }
  return cnt;
}

// FOR TESTING!!!!
uint8_t
HasUnackedRange(struct aDataChunk_t *chunk, uint32_t start, uint32_t end)
{
  struct range32_t *r = chunk->mUnackedRanges;
  while(r) {
    if (r->mStart == start && r->mEnd == end) {
      return 1;
    }
    r = r->mNext;
  }
  return 0;
}

// It always sends from the first mNotSentRange so we only need length.
int32_t
SomeDataSentFromChunk(struct aDataChunk_t *chunk, uint16_t len)
{
  assert(chunk->mNotSentRanges);
  assert(len);
  assert(len <= (chunk->mNotSentRanges->mEnd - chunk->mNotSentRanges->mStart));

  uint32_t start = chunk->mNotSentRanges->mStart;
  uint32_t end = start + len;

  int32_t rv = RemoveRange(&chunk->mNotSentRanges, start, end, NULL);
  if (rv) {
    return rv;
  }
  rv = AddRange(&chunk->mUnackedRanges, start, end);

  LogRanges(chunk);
  return rv;
}

int32_t
AckSomeDataSentFromChunk(struct aDataChunk_t *chunk, uint32_t start,
                         uint32_t end)
{
  assert(end - start);

  uint32_t rv = RemoveRange(&chunk->mUnackedRanges, start, end, NULL);
  if (rv) {
    return rv;
  }

  rv = RemoveRange(&chunk->mNotSentRanges, start, end, NULL);
  if (rv) {
    return rv;
  }
  LogRanges(chunk);

  return 0;
}

int32_t
SomeDataLostFromChunk(struct aDataChunk_t *chunk, uint32_t start,
                         uint32_t end)
{
  assert(end - start);

  struct range32_t *removed = NULL;
  // Remove ranges from mUnackedRanges but only add the actually removed
  // ranges to mNotSentRanges, because some ranges could have been already
  // acked.
  int32_t rv = RemoveRange(&chunk->mUnackedRanges, start, end, &removed);
  if (rv) {
    goto fail;
  }

  while (removed) {
    struct range32_t *r = removed;
    rv = AddRange(&chunk->mNotSentRanges, r->mStart, r->mEnd);
    if (rv) {
      goto fail;
    }

    removed = removed->mNext;
    free(r);
    r = removed;
  }

  LogRanges(chunk);

  return rv;

  fail:
  while (removed) {
    struct range32_t *r = removed;
    removed = removed->mNext;
    free(r);
    r = removed;
  }
  return rv;
}

struct aDataChunkQueue_t
{
  struct aDataChunk_t *mFirst;
  struct aDataChunk_t *mLast;
};

static void
AddChunk(struct aDataChunkQueue_t *queue, struct aDataChunk_t *chunk)
{
  assert(queue);
  assert(chunk);
  chunk->mRefCnt++;

  if (queue->mLast) {
    queue->mLast->mNext = chunk;
    queue->mLast = chunk;
  } else {
    queue->mFirst = queue->mLast = chunk;
  }
}

static void
RemoveChunk(struct aDataChunkQueue_t *queue, struct aDataChunk_t *chunk)
{
  assert(queue);
  assert(chunk);
  struct aDataChunk_t *prev = NULL;
  struct aDataChunk_t *curr = queue->mFirst;
  while (curr && curr != chunk) {
    prev = curr;
    curr = curr->mNext;
  }

  if (curr) {
    if (prev) {
      prev->mNext = curr->mNext;
    } else {
      queue->mFirst = curr->mNext;
    }

    if (curr == queue->mLast) {
      queue->mLast = prev;
    }
  }
  FreeDataChunk(curr);
}

enum StreamState_t
{
  STREAM_IDLE,
  STREAM_OPEN,
  STREAM_CLOSED
};

struct aOutgoingStreamInfo_t
{
  enum StreamState_t mState;
  uint32_t mStreamId;
  uint64_t mNextOffsetToBuffer;
  uint64_t mNextOffsetToSend;
  uint64_t mCanSendOffset;
  uint8_t mStreamReset;
  uint8_t mWaitingForRSTReply;

  struct aDataChunkQueue_t mDataQueue;

  struct aOutgoingStreamInfo_t *mNext;
};

void
SendFrame(struct aOutgoingStreamInfo_t *stream)
{
  assert(stream->mState != STREAM_CLOSED);

  if (stream->mState == STREAM_IDLE) {
    stream->mState = STREAM_OPEN;
  }
}

struct aDataChunkTransmissionElement_t
{
  struct aDataChunk_t *mDataChunk;
  struct aDataChunkTransmissionElement_t *mNext;
};

struct aDataChunkTransmissionQueue_t
{
  struct aDataChunkTransmissionElement_t *mFirst;
  struct aDataChunkTransmissionElement_t *mLast;
};

static int32_t
AddChunkToTransmissionQueue(struct aDataChunkTransmissionQueue_t *queue,
                            struct aDataChunk_t *chunk)
{
  struct aDataChunkTransmissionElement_t *elem =
   (struct aDataChunkTransmissionElement_t *) calloc (1, sizeof(struct aDataChunkTransmissionElement_t));
  if (!elem) {
    return SDTE_OUT_OF_MEMORY;
  }

  elem->mDataChunk = chunk;

  chunk->mRefCnt++;

  if (!queue->mFirst) {
    queue->mFirst = queue->mLast = elem;
  } else {
    queue->mLast->mNext = elem;
    queue->mLast = elem;
  }
  return SDTE_OK;
}

static void
RemoveChunkFromTransmissionQueue(struct aDataChunkTransmissionQueue_t *queue,
                                 struct aDataChunk_t *chunk)
{
  assert(queue->mFirst);

  struct aDataChunkTransmissionElement_t *elemPrev = NULL;
  struct aDataChunkTransmissionElement_t *elemCurr = queue->mFirst;
  while (elemCurr && elemCurr->mDataChunk != chunk) {
    elemPrev = elemCurr;
    elemCurr = elemCurr->mNext;
  }

  // The chunk must be in the queue.
  assert(elemCurr);

  if (!elemPrev) {
    queue->mFirst = elemCurr->mNext;
  } else {
    elemPrev->mNext = elemCurr->mNext;
  }

  if (queue->mLast == elemCurr) {
    queue->mLast = elemPrev;
  }

  FreeDataChunk(elemCurr->mDataChunk);
  free(elemCurr);
}

struct aFrameInfo_t
{
  struct range32_t mRange;
  struct aDataChunk_t *mDataChunk;
  struct aFrameInfo_t *mNext;
};

static void
FreeFrame(struct aFrameInfo_t *frame)
{
  assert(frame->mDataChunk);
  FreeDataChunk(frame->mDataChunk);
  free(frame);
}

// This structure keeps information about a sent packet. It hold info about
// the frames it contains. It is used when the packet is acked to remove the
// acked data.
struct aPacketInfo_t
{
  uint64_t mPacketSeqNum;
  struct aFrameInfo_t *mFrameInfos;
  uint8_t mIsPingPkt;
  uint32_t mSize;
  PRIntervalTime mSentTime;
  struct aPacketInfo_t *mNext;
};

static int32_t
AddFrameInfo(struct aPacketInfo_t *pktInfo, struct aDataChunk_t *chunk,
             uint32_t start, uint32_t end)
{
  assert(chunk);
  assert(end - start);

  struct aFrameInfo_t *frameInfo = (struct aFrameInfo_t*) malloc (sizeof(struct aFrameInfo_t));
  if (!frameInfo) {
    return SDTE_OUT_OF_MEMORY;
  }

  frameInfo->mRange.mStart = start;
  frameInfo->mRange.mEnd = end;
  frameInfo->mDataChunk = chunk;
  chunk->mRefCnt++;

  frameInfo->mNext = NULL;
  if (!pktInfo->mFrameInfos) {
    pktInfo->mFrameInfos = frameInfo;
  } else {
    struct aFrameInfo_t *f = pktInfo->mFrameInfos;
    while (f->mNext) f = f->mNext;
    f->mNext = frameInfo;
  }
  return 0;
}

static void
FreePacketInfo(struct aPacketInfo_t *pktInfo)
{
  while (pktInfo->mFrameInfos) {
    struct aFrameInfo_t *f = pktInfo->mFrameInfos;
    pktInfo->mFrameInfos = pktInfo->mFrameInfos->mNext;
    FreeFrame(f);
  }
}

struct aPacketInfoQueue_t
{
  struct aPacketInfo_t *mFirst;
  struct aPacketInfo_t *mLast;
};

static int32_t
AddPacketInfoToQueue(struct aPacketInfoQueue_t *queue,
                      struct aPacketInfo_t *pktInfo)
{
  pktInfo->mNext = NULL;
  if (!queue->mFirst) {
    queue->mFirst = queue->mLast = pktInfo;
  } else {
    queue->mLast->mNext = pktInfo;
    queue->mLast = pktInfo;
  }
  return SDTE_OK;
}

static void
RemovePacketInfoFromQueue(struct aPacketInfoQueue_t *queue,
                          struct aPacketInfo_t *pktInfo)
{
  assert(queue->mFirst);

  struct aPacketInfo_t *prev = NULL;
  struct aPacketInfo_t *curr = queue->mFirst;
  while (curr && curr != pktInfo) {
    prev = curr;
    curr = curr->mNext;
  }

  // The pktInfo must be in the queue.
  assert(curr);

  if (!prev) {
    queue->mFirst = curr->mNext;
  } else {
    prev->mNext = curr->mNext;
  }

  if (queue->mLast == curr) {
    queue->mLast = prev;
  }
}

static struct aPacketInfo_t *
RemovePacketInfoFromQueueWithId(struct aPacketInfoQueue_t *queue,
                                uint64_t seqNum)
{
  struct aPacketInfo_t *prev = NULL;
  struct aPacketInfo_t *curr = queue->mFirst;
  while (curr) {
    prev = curr;
    curr = curr->mNext;
  }
  prev = NULL;
  curr = queue->mFirst;
  while (curr && curr->mPacketSeqNum != seqNum) {
    prev = curr;
    curr = curr->mNext;
  }

  if (curr) {
    if (!prev) {
      queue->mFirst = curr->mNext;
    } else {
      prev->mNext = curr->mNext;
    }

    if (queue->mLast == curr) {
      queue->mLast = prev;
    }
  }

  return curr;
}

struct SDT_SendDataStruct_t
{
  // Data queues!
  struct aDataChunkQueue_t mOutgoingControlFrames;
  struct aOutgoingStreamInfo_t *mOutgoingStreams;

  // mDataChunkTransmissionQueue holds a list of data chunks that are waiting
  // to be transmitted.
  // TODO: make this a priority queue, e.g. send HEADER up to the last of high
  // priority stream etc.
  struct aDataChunkTransmissionQueue_t mDataChunkTransmissionQueue;

  // Transmitted packet infos (send not acked packets).
  struct aPacketInfoQueue_t mSentPacketInfo;
  // PacketInfo of Lost packets. TODO: dragana - how long to keep them for detecting spurious retransmissions!!!
  struct aPacketInfoQueue_t mLostPacketInfo;

  // Holds the packet info of the packet being sent. The packet is created on
  // the aLayer but finally sent on the sLayer. It is created in the
  // PreparePacket function and deleted or queued in the PacketSent function.
  struct aPacketInfo_t * mPacketBeingSent;

  // The cumulative aount of data that can be sent.
  uint64_t mCanSendSessionOffset;
  // Amount of send data.
  uint64_t mSessionDataSent;
  // This incueds sent data and queued data. This is a cumulative count. We will
  // never queue more than mCanSendSessionOffset, so:
  // mSessionDataSentAndQueued <= mCanSendSessionOffset
  // mSessionDataSent <= mSessionDataSentAndQueued
  uint64_t mSessionDataSentAndQueued;

  // The server rwin for new streams as determined from a SETTINGS frame
  uint32_t mServerInitialStreamWindow;

  // The current amount of outstanding data.
  uint64_t mDataQueued;

  uint8_t mNextToWriteSet;
  uint32_t mNextToWriteId;
};

// FOR TESTING!!!!
struct SDT_SendDataStruct_t *
CreateNewSDTSendDataStr()
{
  return (struct SDT_SendDataStruct_t *) calloc (1, sizeof(struct SDT_SendDataStruct_t));
}

// Helper functions!!!

uint32_t
sdt_send_GetStreamSet(struct SDT_SendDataStruct_t *sendDataStr)
{
  assert(sendDataStr->mNextToWriteSet && // Must be set.
         sendDataStr->mNextToWriteId); // Must not be 0.

  sendDataStr->mNextToWriteSet = 0;
  return sendDataStr->mNextToWriteId;
}


static uint64_t
sdt_send_CanSendData(struct SDT_SendDataStruct_t *sendDataStr)
{
//  fprintf(stderr, "sdt_send_CanSendData queued=%lu send data=%lu "
//          "send and queued data=%lu max=%lu\n",
//          sendDataStr->mDataQueued, sendDataStr->mSessionDataSent,
//          sendDataStr->mSessionDataSentAndQueued,
//          sendDataStr->mCanSendSessionOffset);

  return sendDataStr->mCanSendSessionOffset > sendDataStr->mSessionDataSentAndQueued;
}

static uint64_t
sdt_send_CanSendDataStream(struct SDT_SendDataStruct_t *sendDataStr,
                           struct aOutgoingStreamInfo_t *stream)
{
  fprintf(stderr, "sdt_send_CanSendDataStream queued=%lu send data=%lu "
          "send and queued data=%lu max=%lu\n"
          "streamId=%u, next offset to queue =%lu offset to sent=%lu, can send "
          "offset=%lu\n",
          sendDataStr->mDataQueued, sendDataStr->mSessionDataSent,
          sendDataStr->mSessionDataSentAndQueued,
          sendDataStr->mCanSendSessionOffset, stream->mStreamId,
          stream->mNextOffsetToBuffer, stream->mNextOffsetToSend,
          stream->mCanSendOffset);

  if ((sendDataStr->mCanSendSessionOffset > sendDataStr->mSessionDataSentAndQueued) &&
      (stream->mCanSendOffset > stream->mNextOffsetToBuffer)) {
    uint64_t amount = stream->mCanSendOffset - stream->mNextOffsetToBuffer;
    uint64_t amountSession = sendDataStr->mCanSendSessionOffset -
                              sendDataStr->mSessionDataSentAndQueued;
    return (amountSession > amount) ? amount : amountSession;
  }
  return 0;
}

uint8_t
sdt_send_HasDataForTransmission(struct SDT_SendDataStruct_t *sendDataStr)
{
  return !!(sendDataStr->mDataChunkTransmissionQueue.mFirst);
}

uint8_t
sdt_send_HasUnackedPackets(struct SDT_SendDataStruct_t *sendDataStr)
{
  return !!(sendDataStr->mSentPacketInfo.mFirst);
}

static uint64_t
sdt_send_SmallestPktSeqNumNotAcked(struct SDT_SendDataStruct_t *sendDataStr)
{
  if (!sendDataStr->mSentPacketInfo.mFirst) {
    return 0;
  }
  return sendDataStr->mSentPacketInfo.mFirst->mPacketSeqNum;
}

static int32_t
sdt_send_createStream(struct SDT_SendDataStruct_t *sendDataStr,
                      uint32_t streamId)
{
  struct aOutgoingStreamInfo_t *prev = 0, *curr = sendDataStr->mOutgoingStreams;
  while (curr && (curr->mStreamId < streamId)) {
    prev = curr;
    curr = curr->mNext;
  }
  assert(!curr || (curr->mStreamId != streamId));

  struct aOutgoingStreamInfo_t *stream =
    (struct aOutgoingStreamInfo_t *) malloc (sizeof(struct aOutgoingStreamInfo_t));
  if (!stream) {
    return SDTE_OUT_OF_MEMORY;
  }

  stream->mState = STREAM_IDLE;
  stream->mStreamId = streamId;
  stream->mNextOffsetToSend = 0;
  stream->mNextOffsetToBuffer = 0;
  stream->mCanSendOffset = sendDataStr->mServerInitialStreamWindow;
  stream->mDataQueue.mFirst = NULL;
  stream->mDataQueue.mLast = NULL;
  stream->mStreamReset = 0;
  stream->mWaitingForRSTReply = 0;
  stream->mNext = curr;
  if (!prev) {
    sendDataStr->mOutgoingStreams = stream;
  } else {
    prev->mNext = stream;
  }

  return SDTE_OK;
}

static int32_t
sdt_send_removeStream(struct SDT_SendDataStruct_t *sendDataStr,
                      uint32_t streamId)
{
  struct aOutgoingStreamInfo_t *prev = 0, *curr = sendDataStr->mOutgoingStreams;
  while (curr && (curr->mStreamId != streamId)) {
    prev = curr;
    curr = curr->mNext;
  }
  assert(curr && (curr->mStreamId == streamId));
  assert(!curr->mDataQueue.mFirst);

  if (!prev) {
    sendDataStr->mOutgoingStreams = curr->mNext;
  } else {
    prev->mNext = curr->mNext;
  }

  return SDTE_OK;
}

static struct aOutgoingStreamInfo_t*
sdt_send_FindStream(struct SDT_SendDataStruct_t *sendDataStr,
                    uint32_t streamId)
{
  struct aOutgoingStreamInfo_t *curr = sendDataStr->mOutgoingStreams;
  while (curr && (curr->mStreamId < streamId)) {
    curr = curr->mNext;
  }
  if (!curr || (curr->mStreamId != streamId)) {
    return NULL;
  }
  return curr;
}

// Creating chunk and adding to a queue!!!
static struct aDataChunk_t *
sdt_send_CreateDataChunk(struct SDT_SendDataStruct_t *sendDataStr,
                         struct aOutgoingStreamInfo_t *stream, uint32_t size)
{
  assert(stream && size);
  assert(stream->mNextOffsetToBuffer + size <= stream->mCanSendOffset);
  assert(sendDataStr->mSessionDataSentAndQueued + size <=
         sendDataStr->mCanSendSessionOffset);

  struct aDataChunk_t *chunk = CreateChunk(DATA_CHUNK, size, stream->mStreamId);
  if (!chunk) {
    return NULL;
  }

  chunk->mRefCnt++;

  chunk->mOffset = stream->mNextOffsetToBuffer;
  stream->mNextOffsetToBuffer += size;
  sendDataStr->mSessionDataSentAndQueued += size;
  AddChunk(&stream->mDataQueue, chunk);

  FreeDataChunk(chunk);
  return chunk;
}

static int32_t RemoveChunkFromBuffer(struct SDT_SendDataStruct_t *sendDataStr,
                                     struct aDataChunk_t *chunk);

static int32_t
AddChunkRange(struct SDT_SendDataStruct_t *sendDataStr,
              struct aDataChunk_t *chunk, uint32_t start, uint32_t end);

// This function willl create a contorl chunk and return a pointer to the chunk
// buffer. 
static uint8_t *
sdt_send_CreateControlChunk(struct SDT_SendDataStruct_t *sendDataStr,
                            uint32_t size)
{
  struct aDataChunk_t *chunk = CreateChunk(CONTROL_CHUNK, size, 0);
  if (!chunk) {
    return NULL;
  }

  AddChunk(&sendDataStr->mOutgoingControlFrames, chunk);

  uint32_t rv = AddChunkRange(sendDataStr, chunk, 0, size);

  if (rv) {
    // This can only failed with SDTE_OUT_OF_MEMORY error!
    // Chunk will be freed by RemoveDataChunk.
    RemoveChunkFromBuffer(sendDataStr, chunk);
    return NULL;
  }

  return GetDataChunkBuf(chunk);
}

static struct aDataChunk_t *
sdt_send_CreateDataChunkStreamId(struct SDT_SendDataStruct_t *sendDataStr,
                                 uint32_t streamId, uint32_t size)
{
  struct aOutgoingStreamInfo_t* stream =
    sdt_send_FindStream(sendDataStr, streamId);
  assert(stream);

  return sdt_send_CreateDataChunk(sendDataStr, stream, size);
}

static int32_t
sdt_send_MaybeBufferData(struct SDT_SendDataStruct_t *sendDataStr,
                         const uint8_t *buf, uint32_t amount)
{
  uint32_t streamId = sdt_send_GetStreamSet(sendDataStr);
  assert(streamId);

  fprintf(stderr, "sdt_send_MaybeBufferData: amount=%d streamId=%d\n",
          amount, streamId);

  struct aOutgoingStreamInfo_t* stream =
    sdt_send_FindStream(sendDataStr, streamId);
  assert(stream && stream->mState != STREAM_CLOSED);

  uint64_t canSendAmount = sdt_send_CanSendDataStream(sendDataStr,
                                                      stream);

  fprintf(stderr, "sdt_send_MaybeBufferData: canSendAmount=%lu\n",
          canSendAmount);
  if (!canSendAmount) {
    return SDTE_WOULD_BLOCK;
  }

  canSendAmount = (canSendAmount > amount) ? amount : canSendAmount;

  struct aDataChunk_t *chunk = sdt_send_CreateDataChunk(sendDataStr, stream,
                                                        canSendAmount);

  if (!chunk) {
    return SDTE_OUT_OF_MEMORY;
  }

  unsigned char *chunkBuf = GetDataChunkBuf(chunk);

  memcpy(chunkBuf, buf, canSendAmount);
  int32_t rv = AddChunkRange(sendDataStr, chunk, 0, canSendAmount);
  if (rv) {
    return rv;
  }
  LogRanges(chunk);
  return canSendAmount;
}

static int32_t
sdt_send_CloseStream(struct SDT_SendDataStruct_t *sendDataStr,
                     uint32_t streamId)
{
  // Find stream info.
  struct aOutgoingStreamInfo_t *stream = sdt_send_FindStream(sendDataStr,
                                                             streamId);
  if (!stream) {
    return SDTE_NOT_AVAILABLE;
  }
    
  assert(stream->mState == STREAM_OPEN);
  stream->mState = STREAM_CLOSED;
  struct aDataChunk_t *chunk = sdt_send_CreateDataChunk(sendDataStr, stream, 0);

  if (!chunk) {
    return SDTE_OUT_OF_MEMORY;
  }
  assert(stream->mDataQueue.mLast);
  stream->mDataQueue.mLast->mFin = 1;
  return SDTE_OK;
}


int32_t
sdt_send_RST_STREAM(struct SDT_SendDataStruct_t *sendStr, uint32_t streamId,
                    uint64_t offset)
{
 //TODO!!!!
  return SDTE_OK;
}

static int32_t
sdt_send_ResetStream(struct SDT_SendDataStruct_t *sendDataStr,
                     uint32_t streamId, uint8_t sendRST)
{
  // Find stream info.
  struct aOutgoingStreamInfo_t *stream = sdt_send_FindStream(sendDataStr,
                                                             streamId);
  if (!stream) {
    return SDTE_NOT_AVAILABLE;
  }

  if (!stream->mStreamReset) {
    while (stream->mDataQueue.mFirst) {
      struct aDataChunk_t *chunk = stream->mDataQueue.mFirst;
      if (chunk->mNotSentRanges) {
        RemoveChunkFromTransmissionQueue(&sendDataStr->mDataChunkTransmissionQueue,
                                         chunk);
      }
      if (chunk->mData) {
        sendDataStr->mDataQueued -= chunk->mData->mSize;
        free(chunk->mData);
        chunk->mData = NULL;
      }

      while (chunk->mNotSentRanges) {
         struct range32_t *range = chunk->mNotSentRanges;
         chunk->mNotSentRanges = range->mNext;
         free(range);
      }

      while (chunk->mUnackedRanges) {
         struct range32_t *range = chunk->mUnackedRanges;
         chunk->mUnackedRanges = range->mNext;
         free(range);
      }

      stream->mDataQueue.mFirst = chunk->mNext;
      FreeDataChunk(chunk);
    }

    stream->mDataQueue.mFirst = stream->mDataQueue.mLast = NULL;
    
    assert((sendDataStr->mSessionDataSentAndQueued - sendDataStr->mSessionDataSent) >=
           (stream->mNextOffsetToBuffer - stream->mNextOffsetToSend));
    sendDataStr->mSessionDataSentAndQueued -= stream->mNextOffsetToBuffer - stream->mNextOffsetToSend;
  }

  if (sendRST) {
    assert(!stream->mStreamReset);
    assert(stream->mState != STREAM_CLOSED);
    stream->mWaitingForRSTReply = 1;
    stream->mStreamReset = 1;
    stream->mState = STREAM_CLOSED;
    sdt_send_RST_STREAM(sendDataStr, streamId, stream->mNextOffsetToSend);
  } else {
    if (stream->mState != STREAM_CLOSED) {
      sdt_send_RST_STREAM(sendDataStr, streamId, stream->mNextOffsetToSend);
    }
    stream->mStreamReset = 1;
    stream->mState = STREAM_CLOSED;
  }

  return SDTE_OK;
}

// FOR TESTING !!!!!
struct aDataChunk_t *
CreateDataChunkForTest(struct SDT_SendDataStruct_t *sendDataStr,
                       uint32_t streamId, uint32_t size)
{
  return sdt_send_CreateDataChunkStreamId(sendDataStr, streamId, size);
}

// Clear data structure!!!
static void
ClearSDTSendDataStr(struct SDT_SendDataStruct_t *sendDataStr)
{
  while (sendDataStr->mOutgoingControlFrames.mFirst) {
    struct aDataChunk_t *doneC = sendDataStr->mOutgoingControlFrames.mFirst;
    sendDataStr->mOutgoingControlFrames.mFirst = doneC->mNext;
    FreeDataChunk(doneC);
  }

  struct aOutgoingStreamInfo_t *doneSI, *currSI = sendDataStr->mOutgoingStreams;
  while (currSI) {
    doneSI = currSI;
    currSI = currSI->mNext;
    while (doneSI->mDataQueue.mFirst) {
      struct aDataChunk_t *doneC = doneSI->mDataQueue.mFirst;
      doneSI->mDataQueue.mFirst = doneC->mNext;
      FreeDataChunk(doneC);
    }
    free(doneSI);
  }

  while (sendDataStr->mDataChunkTransmissionQueue.mFirst) {
    struct aDataChunkTransmissionElement_t *elem = sendDataStr->mDataChunkTransmissionQueue.mFirst;
    sendDataStr->mDataChunkTransmissionQueue.mFirst = elem->mNext;
    free(elem);
  }

  while (sendDataStr->mSentPacketInfo.mFirst) {
    struct aPacketInfo_t *pktInfo = sendDataStr->mSentPacketInfo.mFirst;
    sendDataStr->mSentPacketInfo.mFirst = pktInfo->mNext;
    FreePacketInfo(pktInfo);
  }

  while (sendDataStr->mLostPacketInfo.mFirst) {
    struct aPacketInfo_t *pktInfo = sendDataStr->mLostPacketInfo.mFirst;
    sendDataStr->mLostPacketInfo.mFirst = pktInfo->mNext;
    FreePacketInfo(pktInfo);
  }
}

static int32_t
AddChunkRange(struct SDT_SendDataStruct_t *sendDataStr,
              struct aDataChunk_t *chunk, uint32_t start, uint32_t end)
{
  assert(chunk->mData->mWritten == start);
  assert(chunk->mData->mSize >= end);

  uint8_t addForTrans = !chunk->mNotSentRanges;
  uint32_t rv = AddRange(&chunk->mNotSentRanges, start, end);

  if (rv) {
    return rv;
  }

  chunk->mData->mWritten += (end - start);

  if (addForTrans) {
    rv = AddChunkToTransmissionQueue(&sendDataStr->mDataChunkTransmissionQueue, chunk);
    if (rv) {
      return rv;
    }
  }

  sendDataStr->mDataQueued += (end - start);

  LogRanges(chunk);
  return 0;
}

#ifdef H2MAPPING
// Data are written to a chunk using the sdt_send_WriteDataToDataChunk function
// which takes a buffer and does data copy or using the GetDataChunkBuf function
// which returns raw buffer (the user must take care of a buffer overflow). The
// user of GetDataChunkBuf must call AddChunkRange, this function will add the
// corresponding range and do additional necessary steps like adding the chunk
// to the transmission queue etc.
static int32_t
sdt_send_WriteDataToDataChunk(struct SDT_SendDataStruct_t *sendDataStr,
                              struct aDataChunk_t *chunk,
                              const unsigned char *buf, int32_t toWrite)
{
  fprintf(stderr, "sdt_send_WriteDataToDataChunk toWrite=%d \n", toWrite);

  assert(chunk->mData);
  assert(chunk->mData->mSize >= chunk->mData->mWritten + toWrite);

  unsigned char *chunkBuf = GetDataChunkBuf(chunk);

  memcpy(chunkBuf + chunk->mData->mWritten, buf, toWrite);

  int32_t rv = AddChunkRange(sendDataStr, chunk, chunk->mData->mWritten,
                             chunk->mData->mWritten + toWrite);
  if (rv) {
    return rv;
  }

  LogRanges(chunk);
  return toWrite;
}
#endif

static int32_t
SDTFrameSent(struct SDT_SendDataStruct_t *sendDataStr,
             struct aDataChunk_t *chunk, uint16_t len,
             struct aPacketInfo_t *pktInfo)
{
  assert(chunk->mNotSentRanges);

  uint32_t start = chunk->mNotSentRanges->mStart;

  int32_t rv = SomeDataSentFromChunk(chunk, len);
  if (rv) {
    return rv;
  }

  rv = AddFrameInfo(pktInfo, chunk, start, start + len);
  if (rv) {
    return rv;
  }

  if (!chunk->mNotSentRanges) {
    RemoveChunkFromTransmissionQueue(&sendDataStr->mDataChunkTransmissionQueue,
                                     chunk);
  }

  return 0;
}

static uint8_t
WriteControlFrame(struct SDT_SendDataStruct_t *sendDataStr,
                  struct aDataChunk_t *chunk,
                  struct aPacket_t *pkt, struct aPacketInfo_t *pktInfo)
{
  assert(chunk);
  assert(pkt);
  assert(pktInfo);

  uint16_t len = chunk->mNotSentRanges->mEnd - chunk->mNotSentRanges->mStart;

  if ((pkt->mSize - pkt->mWritten) < len) {
    return 0;
  }

  unsigned char *chunkBuf = GetDataChunkBuf(chunk);
  unsigned char *pktBuf = (unsigned char *)(pkt + 1);
  memcpy(pktBuf + pkt->mWritten, chunkBuf, len);
  pkt->mWritten += len;

  if (SDTFrameSent(sendDataStr, chunk, len, pktInfo)) {
    return 0;
  }

  if (chunkBuf[0] == SDT_FRAME_TYPE_PING) {
    pktInfo->mIsPingPkt = 1;
  }

  return 1;
}

static uint8_t
WriteDataFrame(struct SDT_SendDataStruct_t *sendDataStr,
               struct aDataChunk_t *chunk,
               struct aPacket_t *pkt, struct aPacketInfo_t *pktInfo)
{
  fprintf(stderr, "WriteDataFrame\n");
  assert(chunk);
  assert(pkt);
  assert(pktInfo);

  if ((pkt->mSize - pkt->mWritten) <= SDT_FRAME_TYPE_STREAM_HEADER_SIZE) {
    return 0;
  }

  uint16_t lenRemaining = pkt->mSize - pkt->mWritten -
                          SDT_FRAME_TYPE_STREAM_HEADER_SIZE;

  uint16_t len = chunk->mNotSentRanges->mEnd - chunk->mNotSentRanges->mStart;
  len = (len > lenRemaining) ? lenRemaining : len;

  uint8_t fin = 0;
  if (chunk->mFin &&
      ((chunk->mNotSentRanges->mStart + len) == chunk->mData->mSize)) {
    fin = 1;
  }

  // Data frames are streams so we can concatenate data from multiple chunks.
  struct aDataChunk_t *currChunk = chunk;
  while (((lenRemaining > len) &&
          (currChunk->mNotSentRanges->mEnd == currChunk->mData->mSize) &&
          currChunk->mNext &&
          (currChunk->mNext->mOffset == (currChunk->mOffset + currChunk->mData->mSize)) &&
          currChunk->mNext->mNotSentRanges &&
          !currChunk->mNext->mNotSentRanges->mStart
         ) ||
         ((currChunk->mNotSentRanges->mEnd == currChunk->mData->mSize) &&
          currChunk->mNext &&
          (currChunk->mNext->mOffset == (currChunk->mOffset + currChunk->mData->mSize)) &&
          currChunk->mNext->mNotSentRanges &&
          !currChunk->mNext->mNotSentRanges->mStart &&
          !currChunk->mNext->mData->mSize &&
          currChunk->mNext->mFin
         )) {

    currChunk = currChunk->mNext;
    uint64_t lenChunk = currChunk->mNotSentRanges->mEnd - currChunk->mNotSentRanges->mStart;
    if ((len + lenChunk) > lenRemaining) {
      lenChunk = lenRemaining - len;
    }
    len += lenChunk;

    if (currChunk->mFin &&
        ((currChunk->mNotSentRanges->mStart + lenChunk) == currChunk->mData->mSize)) {
      assert(!fin);
      fin = 1;
    }
  }

  unsigned char *pktbuf = (unsigned char *)(pkt + 1);
  int32_t written = sdt_encode_StreamFrame(pktbuf + pkt->mWritten,
                                           chunk->mStreamId, 4,
                                           chunk->mOffset + chunk->mNotSentRanges->mStart,
                                           (chunk->mOffset + chunk->mNotSentRanges->mStart) ? 8 : 0,
                                           fin, 1, len);
  assert(written > 0);
  pkt->mWritten += written;

  uint16_t currLen = 0;
  while (currLen < len) {
    unsigned char *chunkbuf = GetDataChunkBuf(chunk);
    uint16_t toSend = chunk->mNotSentRanges->mEnd - chunk->mNotSentRanges->mStart;
    toSend = (toSend > (len - currLen)) ? len - currLen : toSend;
    memcpy(pktbuf + pkt->mWritten, chunkbuf + chunk->mNotSentRanges->mStart,
           toSend);
    pkt->mWritten += toSend;
    currLen += toSend;
    if (SDTFrameSent(sendDataStr, chunk, toSend, pktInfo)) {
      return 0;
    }
    chunk = chunk->mNext;
  }

  if (fin && chunk && chunk->mData && !chunk->mData->mSize) {
    if (SDTFrameSent(sendDataStr, chunk, 0, pktInfo)) {
      return 0;
    }
  }
  return 1;
}

// This function return true(1) if it has written some new data into the packet
// and false(0) if there is no data to be sent or an error occur (the only
// error that can occur is oom(we should handle this differently)).
static uint8_t
WriteFrame(struct SDT_SendDataStruct_t *sendDataStr,
           struct aPacket_t *pkt,
           struct aPacketInfo_t *pktInfo)
{
  uint8_t rv = 0;

  if (sendDataStr->mDataChunkTransmissionQueue.mFirst) {
    switch(sendDataStr->mDataChunkTransmissionQueue.mFirst->mDataChunk->mType) {
      case CONTROL_CHUNK:
        rv = WriteControlFrame(sendDataStr,
                               sendDataStr->mDataChunkTransmissionQueue.mFirst->mDataChunk,
                               pkt, pktInfo);
        break;
      case DATA_CHUNK:
        rv = WriteDataFrame(sendDataStr,
                            sendDataStr->mDataChunkTransmissionQueue.mFirst->mDataChunk,
                            pkt, pktInfo);
    }

    // If a complete chunk has been sent, SDTFrameSent will delete the chunk
    // from mDataChunkTransmissionQueue!!!
  }
  return rv;
}

int32_t
PreparePacket(struct SDT_SendDataStruct_t *sendDataStr, struct aPacket_t *pkt,
              uint64_t nextPacketId)
{
  assert(!sendDataStr->mPacketBeingSent);
  struct aPacketInfo_t *pktInfo =
    (struct aPacketInfo_t *) calloc (1, sizeof(struct aPacketInfo_t));
  if (!pktInfo) {
    return SDTE_OUT_OF_MEMORY;
  }

  while (WriteFrame(sendDataStr, pkt, pktInfo)) {
    // If we have real data not just an ack, set the packet sequence number,
    // because we need to remember this packet for retransmissions.
    if (!sendDataStr->mPacketBeingSent) {
      pktInfo->mPacketSeqNum = nextPacketId;
      sendDataStr->mPacketBeingSent = pktInfo;
    }
  }

  if (!sendDataStr->mPacketBeingSent) {
    FreePacketInfo(pktInfo);
  }
  return 0;
}

static uint8_t
PacketNeedAck(struct SDT_SendDataStruct_t *sendDataStr)
{
  return !!(sendDataStr->mPacketBeingSent);
}

uint8_t
PacketSent(struct SDT_SendDataStruct_t *sendDataStr, uint8_t sent)
{
  if (sendDataStr->mPacketBeingSent) {
    if (sent) {
      sendDataStr->mPacketBeingSent->mSentTime = PR_IntervalNow();
      AddPacketInfoToQueue(&sendDataStr->mSentPacketInfo,
                           sendDataStr->mPacketBeingSent);

      struct aFrameInfo_t *frame = sendDataStr->mPacketBeingSent->mFrameInfos;
      while (frame) {
        // Find stream info.
        struct aOutgoingStreamInfo_t *stream = sdt_send_FindStream(sendDataStr,
                                                                   frame->mDataChunk->mStreamId);
        uint64_t lastOffset = frame->mDataChunk->mOffset + frame->mRange.mEnd;
        assert(stream->mNextOffsetToBuffer <= lastOffset);
        if (stream->mNextOffsetToSend < lastOffset) {
          assert(sendDataStr->mSessionDataSentAndQueued >=
                 (lastOffset - stream->mNextOffsetToSend + sendDataStr->mSessionDataSent));
          sendDataStr->mSessionDataSent += (lastOffset - stream->mNextOffsetToSend);
          stream->mNextOffsetToSend = lastOffset;
        }
      }
    } else {
      // The packet has not been sent. We need to revert the action.
      struct aFrameInfo_t *frame = sendDataStr->mPacketBeingSent->mFrameInfos;
      while (frame) {
        uint8_t addForTrans = !frame->mDataChunk->mNotSentRanges;

        // This function has a strange name but it does what we want. e.g. move
        // range from unacked to notSent.
        SomeDataLostFromChunk(frame->mDataChunk, frame->mRange.mStart,
                              frame->mRange.mEnd);

        if (addForTrans && frame->mDataChunk->mNotSentRanges) {
          int32_t rv = AddChunkToTransmissionQueue(&sendDataStr->mDataChunkTransmissionQueue,
                                                   frame->mDataChunk);
          if (rv) {
            FreePacketInfo(sendDataStr->mPacketBeingSent);
            sendDataStr->mPacketBeingSent = NULL;
            return 0;
          }
        }
        frame = frame->mNext;
      }
      FreePacketInfo(sendDataStr->mPacketBeingSent);
    }
    sendDataStr->mPacketBeingSent = NULL;
    return 1;
  }
  return 0;
}

// Marking a packet as lost!!!
static int32_t
MarkPacketLost(struct SDT_SendDataStruct_t *sendDataStr,
               struct aPacketInfo_t *pkt)
{
  assert(pkt);
  assert(sendDataStr->mSentPacketInfo.mFirst ||
         sendDataStr->mLostPacketInfo.mFirst);

  struct aFrameInfo_t *frame = pkt->mFrameInfos;
  while (frame) {
    uint8_t addForTrans = !frame->mDataChunk->mNotSentRanges;

    SomeDataLostFromChunk(frame->mDataChunk, frame->mRange.mStart,
                          frame->mRange.mEnd);

    if (addForTrans && frame->mDataChunk->mNotSentRanges) {
      int32_t rv =
        AddChunkToTransmissionQueue(&sendDataStr->mDataChunkTransmissionQueue,
                                    frame->mDataChunk);
      if (rv) {
        return rv;
      }
    }
    frame = frame->mNext;
  }

  RemovePacketInfoFromQueue(&sendDataStr->mSentPacketInfo, pkt);

  AddPacketInfoToQueue(&sendDataStr->mLostPacketInfo, pkt);

  return SDTE_OK;
}

// FOR TESTING!!!!
int32_t
MarkPacketLostWithId(struct SDT_SendDataStruct_t *sendDataStr,
                     uint32_t pktSeqNum)
{
  assert(sendDataStr->mSentPacketInfo.mFirst);
  struct aPacketInfo_t *pkt = sendDataStr->mSentPacketInfo.mFirst;
  while (pkt && pkt->mPacketSeqNum != pktSeqNum) {
    pkt = pkt->mNext;
  }

  if (!pkt) {
    pkt = sendDataStr->mLostPacketInfo.mFirst;
    while (pkt && pkt->mPacketSeqNum != pktSeqNum) {
      pkt = pkt->mNext;
    }
  }

  if (!pkt) {
    return -1;
  }

  return MarkPacketLost(sendDataStr, pkt);
}

// Removing chunks!!!!
static int32_t
RemoveChunkFromBuffer(struct SDT_SendDataStruct_t *sendDataStr,
                      struct aDataChunk_t *chunk)
{
  switch(chunk->mType) {
  case CONTROL_CHUNK:
    RemoveChunk(&sendDataStr->mOutgoingControlFrames, chunk);
    break;
  case DATA_CHUNK:
  {
    // Find stream info.
    struct aOutgoingStreamInfo_t *stream = sdt_send_FindStream(sendDataStr,
                                                               chunk->mStreamId);
    if (!stream) {
      FreeDataChunk(chunk);
      return -1;
    }
    RemoveChunk(&stream->mDataQueue, chunk);
  }
  }

  sendDataStr->mDataQueued -= chunk->mData->mSize;
  free(chunk->mData);
  chunk->mData = NULL;
  return 0;
}

static struct aPacketInfo_t *
PacketAcked(struct SDT_SendDataStruct_t *sendDataStr, uint64_t seqNum)
{
  struct aPacketInfo_t *pkt =
    RemovePacketInfoFromQueueWithId(&sendDataStr->mSentPacketInfo, seqNum);

  if (!pkt) {
    // Check if it is marked as lost!
    pkt = RemovePacketInfoFromQueueWithId(&sendDataStr->mLostPacketInfo, seqNum);
    // spurious retransmission!!!!
  }

  if (!pkt) {
    return NULL;
  }

  while (pkt->mFrameInfos) {
    struct aFrameInfo_t *frame = pkt->mFrameInfos;

    uint8_t hadNotSentData = !!(frame->mDataChunk->mNotSentRanges);
    AckSomeDataSentFromChunk(frame->mDataChunk, frame->mRange.mStart,
                             frame->mRange.mEnd);
    if (hadNotSentData && !frame->mDataChunk->mNotSentRanges) {
      RemoveChunkFromTransmissionQueue(&sendDataStr->mDataChunkTransmissionQueue,
                                       frame->mDataChunk);
    }

    // If everything is acked, free data buffer!
    if (!frame->mDataChunk->mNotSentRanges && !frame->mDataChunk->mUnackedRanges &&
        frame->mDataChunk->mData && (frame->mDataChunk->mData->mSize == frame->mDataChunk->mData->mWritten)) {
      // Everything was acked!
      // Remove the chunk from the stream and delete its data!
      RemoveChunkFromBuffer(sendDataStr, frame->mDataChunk);
      assert(frame->mDataChunk->mData == NULL);
    }
    pkt->mFrameInfos = pkt->mFrameInfos->mNext;
    FreeFrame(frame);
  }
  return pkt;
}

static int32_t
sdt_send_WINDOW_UPDATE(struct SDT_SendDataStruct_t *sendDataStr,
                       uint32_t streamId, uint64_t offset)
{
  fprintf(stderr, "Send WINDOW_UPDATE for stream %u offset=%lu\n",
                  streamId, offset);

  // Chunk is own by sendDataStr!!!!
  uint8_t *chunkBuf = sdt_send_CreateControlChunk(sendDataStr, 13);

  if (!chunkBuf) {
    return SDTE_OUT_OF_MEMORY;
  }

  chunkBuf[0] = SDT_FRAME_TYPE_WINDOW_UPDATE;
  streamId = htonl(streamId);
  memcpy(chunkBuf + 1, &streamId, 4);
  offset = htonll(offset);
  memcpy(chunkBuf + 5, &offset, 8);

  return SDTE_OK;
}

static int32_t
sdt_send_PING(struct SDT_SendDataStruct_t *sendDataStr)
{
  fprintf(stderr, "Send PING.\n");

  // Chunk is own by sendDataStr!!!!
  uint8_t *chunkBuf = sdt_send_CreateControlChunk(sendDataStr, 1);

  if (!chunkBuf) {
    return SDTE_OUT_OF_MEMORY;
  }

  chunkBuf[0] = SDT_FRAME_TYPE_PING;
}

static int32_t
sdt_send_GOAWAY(struct SDT_SendDataStruct_t *sendDataStr, uint32_t error,
                uint32_t lastGoodStream, uint16_t reasonLen,
                const unsigned char *reason)
{
  fprintf(stderr, "Send GOAWAY\n");

  // Chunk is own by sendDataStr!!!!
  uint8_t *chunkBuf = sdt_send_CreateControlChunk(sendDataStr, 11 + reasonLen);

  if (!chunkBuf) {
    return SDTE_OUT_OF_MEMORY;
  }

  chunkBuf[0] = SDT_FRAME_TYPE_GOAWAY;
  error = htonl(error);
  memcpy(chunkBuf + 1, &error, 4);
  lastGoodStream = htonl(lastGoodStream);
  memcpy(chunkBuf + 5, &lastGoodStream, 4);
  reasonLen = htons(reasonLen);
  memcpy(chunkBuf + 9, &reasonLen, 2);
  memcpy(chunkBuf + 9, reason, reasonLen);

  return SDTE_OK;
}

enum SDTH2SState {
  SDT_H2S_NEWFRAME,
  SDT_H2S_FILLFRAME,
  SDT_H2S_PADDING
};

enum SDTConnectionState {
  SDT_CONNECTING, // Until DTLS handshake finishes
  SDT_TRANSFERRING,
  SDT_CLOSING
};

struct recvDataFrame_t
{
  uint8_t mType;
  uint64_t mOffset;
  uint8_t mLast;
  uint16_t mDataSize;
  uint16_t mDataRead;
  struct recvDataFrame_t* mNext;
  // the buffer lives at the end of the struct
};

struct recvStream_t
{
  enum StreamState_t mState;
  uint32_t mStreamId;
  uint64_t mOffset; // Next offset to give to the app.
  uint64_t mCanSendOffset;
  uint64_t mWindowSize;
  uint64_t mNotAckedOffset;
  uint64_t mLastSentOffset;

  uint8_t mHeaderDone;
  uint8_t mStreamReset;
  uint8_t mWaitingForRSTReply;
  uint64_t mEndOffset; // Final byte offset sent on the stream.
  struct recvDataFrame_t *mFrames;
  struct recvStream_t *mNext;

  // This is pointer use only for mReadyStreamsFirst queue!
  struct recvStream_t *mNextReadyStream;
};

static void
FreeRecvStream(struct recvStream_t *stream)
{
  struct recvDataFrame_t *done = stream->mFrames;
  while (done) {
    stream->mFrames = done->mNext;
    free(done);
    done = stream->mFrames;
  }
  free(stream);
}

static void
RecvFrame(struct recvStream_t *stream)
{
  assert(stream->mState != STREAM_CLOSED);

  stream->mState = STREAM_OPEN;
}

static void
RecvFin(struct recvStream_t *stream)
{
  assert(stream->mState == STREAM_OPEN);

  stream->mState = STREAM_CLOSED;
}

struct SDT_RecvDataStruct_t
{
  // This are structures for ordering incoming frames.
  struct recvStream_t *mIncomingStreams;
  uint64_t mSessionOffset;
  uint64_t mCanSendSessionOffset;
  uint64_t mNotAckedOffset;
  uint64_t mLastSentOffset;

#ifdef H2MAPPING
  struct recvDataFrame_t *mH2OrderedFramesLast;
  struct recvDataFrame_t *mH2OrderedFramesFirst;

  uint8_t mH2MagicHello;
  // ONLY H2 MAPPING HELPER VARIABLES!!!
  struct recvDataFrame_t *mH2Header_Frame;
  uint8_t mH2Header_HeaderBuf[HTTP2_HEADERLEN];
  uint32_t mH2Header_Read;
  uint8_t  mH2Header_Fin;
  uint32_t mH2Header_Stream;

#else
  uint32_t mReadyStreamsNum;
  struct recvStream_t *mReadyStreamsFirst;
  struct recvStream_t *mReadyStreamsLast;

  uint8_t mNextToReadSet;
  uint32_t mNextToReadId;
#endif

  // The initial value of the local stream and session window
  uint32_t mInitialRwin;

  // The send structure is needed fpr sending control frames like WINDOW_UPDATE.
  struct SDT_SendDataStruct_t *mSendStr;
};

static void
ClearSDTRecvDataStr(struct SDT_RecvDataStruct_t *recvStr)
{
  struct recvStream_t *doneS, *currS = recvStr->mIncomingStreams;
  while (currS) {
    doneS = currS;
    currS = currS->mNext;
    FreeRecvStream(doneS);
  }

#ifdef H2MAPPING
  struct recvDataFrame_t *doneF, *currF = recvStr->mH2OrderedFramesFirst;
  while (currF) {
    doneF = currF;
    currF = currF->mNext;
    free(doneF);
  }
#endif
}

static struct recvStream_t*
sdt_recv_FindStream(struct SDT_RecvDataStruct_t *recvStr,
                    uint32_t streamId)
{
  struct recvStream_t *curr = recvStr->mIncomingStreams;
  while (curr && (curr->mStreamId < streamId)) {
    curr = curr->mNext;
  }
  if (!curr || (curr->mStreamId != streamId)) {
    return NULL;
  }
  return curr;
}

static void
sdt_recv_IncrementWindowForSession(struct SDT_RecvDataStruct_t *recvStr,
                                   uint32_t bytes)
{
  if (bytes) {
    recvStr->mNotAckedOffset += bytes;
    recvStr->mLastSentOffset = recvStr->mCanSendSessionOffset +
                               recvStr->mNotAckedOffset;
    sdt_send_WINDOW_UPDATE(recvStr->mSendStr, 0, recvStr->mLastSentOffset);
  }
}

static void
sdt_recv_IncrementWindowForStream(struct SDT_RecvDataStruct_t *recvStr,
                                  struct recvStream_t *stream, uint32_t bytes)
{
  if (bytes) {
    stream->mNotAckedOffset += bytes;
    sdt_send_WINDOW_UPDATE(recvStr->mSendStr, stream->mStreamId,
                           stream->mCanSendOffset + stream->mNotAckedOffset);
  }
}

#ifdef H2MAPPING

static int H2_MakeMagicFrame(struct SDT_RecvDataStruct_t *recvStr);
static int32_t H2_MakeSettingsSettingsAckFrame(struct SDT_RecvDataStruct_t *recvStr,
                                               uint8_t ack);

// This frames are ready to be given to Http2.
static int32_t
H2_AddSortedHttp2Frame(struct SDT_RecvDataStruct_t *recvStr,
                       struct recvDataFrame_t *frame)
{
  fprintf(stderr, "H2_AddSortedHttp2Frame %p size=%d \n",
          frame, frame->mDataSize);
    // If there is no magic sent we need to sent it and settings too.
  if (!recvStr->mH2MagicHello) {
    recvStr->mH2MagicHello = 1;
    int32_t rc = H2_MakeMagicFrame(recvStr);
    if (rc) {
      return rc;
    }
    rc = H2_MakeSettingsSettingsAckFrame(recvStr, 0);
    if (rc) {
      return rc;
    }
  }

  assert(!frame->mNext);

  if (recvStr->mH2OrderedFramesLast) {
    recvStr->mH2OrderedFramesLast->mNext = frame;
  } else {
    recvStr->mH2OrderedFramesFirst = frame;
  }
  recvStr->mH2OrderedFramesLast = frame;
  return SDTE_OK;
}

static int32_t
H2_MakeMagicFrame(struct SDT_RecvDataStruct_t *recvStr)
{
  struct recvDataFrame_t *frame =
    (struct recvDataFrame_t*) malloc (sizeof(struct recvDataFrame_t) + 24);
  if (!frame) {
    return SDTE_OUT_OF_MEMORY;
  }
  frame->mNext = 0;
  frame->mOffset = 0;
  frame->mDataSize = 24;
  frame->mDataRead = 0;
  frame->mLast = 0;

  uint8_t *framebuf = (uint8_t*)(frame + 1);
  memcpy(framebuf, magicHello, 24);
  return H2_AddSortedHttp2Frame(recvStr, frame);
}

static int32_t
H2_MakeSettingsSettingsAckFrame(struct SDT_RecvDataStruct_t *recvStr,
                                uint8_t ack)
{
  uint16_t frameLen = HTTP2_HEADERLEN + (ack ? 0 : 18);

  struct recvDataFrame_t *frame =
    (struct recvDataFrame_t*) malloc (sizeof(struct recvDataFrame_t) +
                                      frameLen);
  if (!frame) {
    return SDTE_OUT_OF_MEMORY;
  }
  frame->mNext = 0;
  frame->mOffset = 0;
  frame->mDataSize = 0;
  frame->mDataRead = 0;
  frame->mLast = 0;

  uint8_t *framebuf = (uint8_t*)(frame + 1);

  framebuf[frame->mDataSize] = 0;
  frame->mDataSize += 1;

  uint16_t len = ack ? 0 : 18;
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
    framebuf[frame->mDataSize + 1] = HTTP2_SETTINGS_TYPE_HEADER_TABLE_SIZE;
    uint32_t val = htonl(65536);
    memcpy(framebuf + frame->mDataSize + 2, &val, 4);
    frame->mDataSize += 6;

    framebuf[frame->mDataSize] = 0;
    framebuf[frame->mDataSize + 1] = HTTP2_SETTINGS_TYPE_INITIAL_WINDOW;
    val = htonl(131072);
    memcpy(framebuf + frame->mDataSize + 2, &val, 4);
    frame->mDataSize += 6;

    framebuf[frame->mDataSize] = 0;
    framebuf[frame->mDataSize + 1] = HTTP2_SETTINGS_MAX_FRAME_SIZE;
    val = htonl( 0x4000);
    memcpy(framebuf + frame->mDataSize + 2, &val, 4);
    frame->mDataSize += 6;
  }
  return H2_AddSortedHttp2Frame(recvStr, frame);
}

static int32_t
H2_Make_PING_ACK(struct SDT_RecvDataStruct_t *recvStr)
{
  // A ping packet was been acked, send an h2 ping ack.
  fprintf(stderr, "Make HTTP2 PING ACK.\n");
  struct recvDataFrame_t *frame =
    (struct recvDataFrame_t*) malloc (sizeof(struct recvDataFrame_t) +
                                      HTTP2_HEADERLEN + 8);
  if (!frame)
    return SDTE_OUT_OF_MEMORY;

  frame->mNext = 0;
  frame->mOffset = 0;
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
  return H2_AddSortedHttp2Frame(recvStr, frame);
}

uint8_t
H2_IsDataStream(uint32_t streamId)
{
  streamId = streamId & 0x3;
  return (streamId == 3) || (streamId == 0);
}

uint32_t
H2_SDTStreamId2H2(uint32_t streamId)
{
  if (streamId & (uint32_t)0x1) {
    streamId = streamId >> 2;
  } else {
    streamId = streamId >> 1;
    if (streamId & (uint32_t)0x1) {
      streamId++;
    }
  }
  return streamId;
}

static int32_t
H2_Make_RST_STREAM(struct SDT_RecvDataStruct_t *recvStr, uint32_t streamId,
                   uint32_t offset)
{
  // RST only when the data stream is reset not header stream!
  if (!H2_IsDataStream(streamId)) {
    return SDTE_OK;
  }

  // I am going to queue this one as if it is a data packet
  struct recvDataFrame_t *frame =
    (struct recvDataFrame_t*) malloc (sizeof(struct recvDataFrame_t) +
                                      HTTP2_HEADERLEN + 4);
  if (!frame) {
    return SDTE_OUT_OF_MEMORY;
  }

  frame->mType = HTTP2_FRAME_TYPE_RST_STREAM;
  frame->mNext = 0;
  frame->mOffset = 0;
  frame->mDataSize = HTTP2_HEADERLEN + 4;
  frame->mDataRead = 0;
  frame->mLast = 1;

  uint8_t *buf = (uint8_t*)(frame + 1);
  buf[0] = 0;
  uint16_t lenN = htons(4);
  memcpy(buf + 1, &lenN, 2);
  buf[3] = HTTP2_FRAME_TYPE_RST_STREAM;
  buf[4] = 0;

  assert((streamId != 1) && (streamId != 3));
  uint32_t h2Stream = H2_SDTStreamId2H2(streamId);
  h2Stream = htonl(h2Stream);
  memcpy(buf + 5, &h2Stream, 4);
  offset = htonl(offset);
  memcpy(buf + HTTP2_HEADERLEN, &offset, 4);

  return H2_AddSortedHttp2Frame(recvStr, frame);
}

static int32_t
H2_Make_GOAWAY(struct SDT_RecvDataStruct_t *recvStr, uint32_t streamId,
               uint32_t errorCode, uint8_t *buf, uint16_t len)
{
  struct recvDataFrame_t *frame =
    (struct recvDataFrame_t*)malloc(sizeof(struct recvDataFrame_t) + HTTP2_HEADERLEN + 8 +
                             len);
  if (!frame) {
    return SDTE_OUT_OF_MEMORY;
  }

  frame->mType = HTTP2_FRAME_TYPE_GOAWAY;
  frame->mNext = 0;
  frame->mOffset = 0;
  frame->mDataSize = HTTP2_HEADERLEN + 8 + len;
  frame->mDataRead = 0;
  frame->mLast = 0;

  uint8_t *frameBuf = (uint8_t*)(frame + 1);

  frameBuf[0] = 0;
  uint16_t lenN = htons(8 + len);
  memcpy(frameBuf + 1, &lenN, 2);
  frameBuf[3] = HTTP2_FRAME_TYPE_GOAWAY;
  frameBuf[4] = 0;
  memset(frameBuf + 5, 0, 4);

  assert((streamId != 1) && (streamId != 3));
  uint32_t h2Stream = H2_SDTStreamId2H2(streamId);
  h2Stream = htonl(h2Stream);
  memcpy(frameBuf + HTTP2_HEADERLEN, &h2Stream, 4);

  errorCode = htonl(errorCode);
  memcpy(frameBuf + HTTP2_HEADERLEN + 4, &errorCode, 4);

  memcpy(frameBuf + HTTP2_HEADERLEN+ 8, buf, len);

  return H2_AddSortedHttp2Frame(recvStr, frame);
}

static int32_t
H2_Make_WINDOW_UPDATE(struct SDT_RecvDataStruct_t *recvStr, uint32_t streamId,
                      uint64_t increment)
{
  while (increment) {
    uint32_t incr;
    if (increment > (uint32_t)(2<< (31 - 1))) {
      incr = (2<< (31 - 1));
    } else {
      incr = increment;
    }

    struct recvDataFrame_t *frame = (struct recvDataFrame_t*)malloc(sizeof(struct recvDataFrame_t) +
                                                      HTTP2_HEADERLEN + 4);
    if (!frame) {
      return SDTE_OUT_OF_MEMORY;
    }

    frame->mNext = 0;
    frame->mOffset = 0;
    frame->mDataSize = HTTP2_HEADERLEN + 4;
    frame->mDataRead = 0;
    frame->mLast = 0;

    uint8_t *buf = (uint8_t*)(frame + 1);
    buf[0] = 0;
    uint16_t len = htons(4);
    memcpy(buf + 1, &len, 2);
    buf[3] = HTTP2_FRAME_TYPE_WINDOW_UPDATE;
    buf[4] = 0;

    assert((streamId != 1) && (streamId != 3));
    uint32_t h2Stream = H2_SDTStreamId2H2(streamId);
    h2Stream = htonl(h2Stream);
    memcpy(buf + 5, &h2Stream, 4);

    incr = htonl(incr);
    memcpy(buf + HTTP2_HEADERLEN, &incr, 4);
    int32_t rv = H2_AddSortedHttp2Frame(recvStr, frame);
    if (rv) {
      return rv;
    }
  }
  return SDTE_OK;
}

static int32_t
H2_Make_STREAM_FRAME(struct SDT_RecvDataStruct_t *recvStr, uint32_t streamId,
                     const uint8_t *data, uint16_t len)
{
  struct recvDataFrame_t *frame =
    (struct recvDataFrame_t*)malloc(sizeof(struct recvDataFrame_t) +
                             HTTP2_HEADERLEN + len);
  if (!frame) {
    return SDTE_OUT_OF_MEMORY;
  }

  frame->mType = HTTP2_FRAME_TYPE_RST_STREAM;
  frame->mNext = 0;
  frame->mOffset = 0;
  frame->mDataSize = HTTP2_HEADERLEN + len;
  frame->mDataRead = 0;

  uint8_t *buf = (uint8_t*)(frame + 1);
  buf[0] = 0;
  uint16_t dataLen = htons(len);
  memcpy(buf + 1, &dataLen, 2);
  buf[3] = HTTP2_FRAME_TYPE_DATA;
  buf[4] = (frame->mLast) ? HTTP2_FRAME_FLAG_END_STREAM : 0;

  assert((streamId != 1) && (streamId != 3));
  uint32_t h2Stream = H2_SDTStreamId2H2(streamId);
  h2Stream = htonl(h2Stream);
  memcpy(buf + 5, &h2Stream, 4);
  memcpy(buf + HTTP2_HEADERLEN, data, len);
  return H2_AddSortedHttp2Frame(recvStr, frame);
}

static int32_t
H2_Make_PING(struct SDT_RecvDataStruct_t *recvStr)
{
  struct recvDataFrame_t *frame =
    (struct recvDataFrame_t*)malloc(sizeof(struct recvDataFrame_t) +
                             HTTP2_HEADERLEN + 8);
  if (!frame) {
    return SDTE_OUT_OF_MEMORY;
  }

  frame->mNext = 0;
  frame->mOffset = 0;
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
  return H2_AddSortedHttp2Frame(recvStr, frame);
}

struct sdt_t;
int32_t sdt_EnsureStreamCreated(struct sdt_t *handle, uint32_t streamId);

static int
H2_OrderFramesReadyForApp(struct SDT_RecvDataStruct_t *recvStr,
                          struct sdt_t *handle,
                          struct recvStream_t* stream)
{
// TODO CONTINUATION frames will not work properly!!!!!!!
  assert(stream->mStreamId != 1);
  if (!stream->mHeaderDone && stream->mStreamId != 3) {
    return 0;
  }

  // Check if we have some ordered packets.
  while (stream->mFrames && (stream->mOffset == stream->mFrames->mOffset)) {
    struct recvDataFrame_t *frameOrd = stream->mFrames;

    stream->mFrames = stream->mFrames->mNext;
    frameOrd->mNext = NULL;
    stream->mOffset += frameOrd->mDataSize;

    fprintf(stderr, "H2_OrderFramesReadyForApp one done %lu %d\n",
            frameOrd->mOffset, frameOrd->mDataSize);

    if (stream->mStreamId != 3) {
      int32_t rv = H2_Make_STREAM_FRAME(recvStr, stream->mStreamId,
                                        (uint8_t*)(frameOrd + 1),
                                        frameOrd->mDataSize);
      if (rv) {
        return rv;
      }
    } else {
      uint32_t len = frameOrd->mDataSize;
      uint8_t *buf = (uint8_t*)(frameOrd + 1);
fprintf(stderr, "DDDDDD1 %d %p %d %d\n", len, recvStr->mH2Header_Frame,
        recvStr->mH2Header_Read, HTTP2_HEADERLEN);
      while (len) {
        if (!recvStr->mH2Header_Frame) {
          uint32_t headerLen = HTTP2_HEADERLEN - recvStr->mH2Header_Read;
          headerLen = (len > headerLen) ? headerLen : len;
fprintf(stderr, "DDDDD2 %d\n", headerLen);
          memcpy(recvStr->mH2Header_HeaderBuf + recvStr->mH2Header_Read,
                 buf, headerLen);
          len -=  headerLen;
          recvStr->mH2Header_Read += headerLen;

          assert (recvStr->mH2Header_Read <= HTTP2_HEADERLEN);
fprintf(stderr, "DDDDD2 %d\n", recvStr->mH2Header_Read);
          if (recvStr->mH2Header_Read == HTTP2_HEADERLEN) {
            uint16_t frameLen;
            memcpy(&frameLen, recvStr->mH2Header_HeaderBuf + 1, 2);
            frameLen = ntohs(frameLen);

            recvStr->mH2Header_Frame = (struct recvDataFrame_t *) malloc (sizeof(struct recvDataFrame_t) +
                                                                          HTTP2_HEADERLEN +
                                                                          frameLen);
            if (!recvStr->mH2Header_Frame) {
              return SDTE_OUT_OF_MEMORY;
            }
            recvStr->mH2Header_Frame->mNext = 0;
            recvStr->mH2Header_Frame->mOffset = 0;
            recvStr->mH2Header_Frame->mDataSize = HTTP2_HEADERLEN + frameLen;
            recvStr->mH2Header_Frame->mDataRead = 0;
            recvStr->mH2Header_Frame->mLast = 0;
            uint8_t *frameBuf = (uint8_t*)(recvStr->mH2Header_Frame + 1);

fprintf(stderr, "DDDDD2 %p %d %d\n", recvStr->mH2Header_Frame, recvStr->mH2Header_Frame->mDataSize, recvStr->mH2Header_Read);
            memcpy(frameBuf, recvStr->mH2Header_HeaderBuf, HTTP2_HEADERLEN);

            recvStr->mH2Header_Fin = recvStr->mH2Header_HeaderBuf[4] & HTTP2_FRAME_FLAG_END_HEADERS;
            if (recvStr->mH2Header_Fin) {
              memcpy(&recvStr->mH2Header_Stream,
                     recvStr->mH2Header_HeaderBuf + 5, 4);
              recvStr->mH2Header_Stream = ntohl(recvStr->mH2Header_Stream);

              int32_t rv = sdt_EnsureStreamCreated(handle,
                                                   recvStr->mH2Header_Stream);
              if (rv) {
                return rv;
              }
            }
          }
        } else {
          uint32_t toRead = recvStr->mH2Header_Frame->mDataSize - recvStr->mH2Header_Read;
          toRead = (len > toRead) ? toRead : len;
          uint8_t *frameBuf = (uint8_t*)(recvStr->mH2Header_Frame + 1);
          memcpy(frameBuf + recvStr->mH2Header_Read, buf, toRead);
fprintf(stderr, "DDDDD2 %p %d %d %d %d\n", recvStr->mH2Header_Frame, recvStr->mH2Header_Frame->mDataSize, recvStr->mH2Header_Read, toRead, len);
          len -= toRead;
          recvStr->mH2Header_Read += toRead;
        }

        if (recvStr->mH2Header_Frame &&
            (recvStr->mH2Header_Read == recvStr->mH2Header_Frame->mDataSize)) {
          int32_t rv = H2_AddSortedHttp2Frame(recvStr, recvStr->mH2Header_Frame);
          if (rv) {
            return rv;
          }

          recvStr->mH2Header_Frame = NULL;
          recvStr->mH2Header_Read = 0;
          if (recvStr->mH2Header_Fin) {
            assert(recvStr->mH2Header_Stream);
            struct recvStream_t* dataStream = sdt_recv_FindStream(recvStr,
                                                                  recvStr->mH2Header_Stream);
            if (dataStream) {
              // It can be that the stream is already closed!
              dataStream->mHeaderDone = 1;
              int rv = H2_OrderFramesReadyForApp(recvStr, handle, dataStream);
              if (rv) {
                return rv;
              }
            }
          }
          recvStr->mH2Header_Stream = 0;
          recvStr->mH2Header_Fin = 0;
        }
      }
    }
  }
  return SDTE_OK;
}

static int
H2_Recv(struct SDT_RecvDataStruct_t *recvStr, void *buf, int32_t amount,
        int flags)
{
  fprintf(stderr, "H2_Recv amount=%d\n", amount);
  if (!recvStr->mH2OrderedFramesFirst) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
  // Making it so complicated because of PR_MSG_PEEK.
  struct recvDataFrame_t *frame = recvStr->mH2OrderedFramesFirst;
  uint32_t frameSize = frame->mDataSize;
  uint32_t frameAlreadyRead = frame->mDataRead;
  int32_t read = 0;
  while ((read < amount) && frame) {
    fprintf(stderr, "H2_Recv read=%d next frame data size=%d read=%d\n",
            read, frameSize, frameAlreadyRead);
    uint8_t *framebuf = (uint8_t*)(frame + 1);
    int32_t toRead = frameSize - frameAlreadyRead;
    toRead = (toRead > (amount - read)) ? (amount - read) : toRead;
    memcpy((uint8_t *)buf + read,
           framebuf + frameAlreadyRead,
           toRead);
    read += toRead;
    if (!(flags & PR_MSG_PEEK)) {
      recvStr->mH2OrderedFramesFirst->mDataRead += toRead;
    }
    frameAlreadyRead += toRead;
    if (frameAlreadyRead == frameSize) {
      frame = frame->mNext;
      if (frame) {
        frameSize = frame->mDataSize;
        frameAlreadyRead = frame->mDataRead;
      }
fprintf(stderr, "DDDDD  %p %p\n", recvStr->mH2OrderedFramesFirst, frame);
      if (!(flags & PR_MSG_PEEK)) {
        struct recvDataFrame_t *done = recvStr->mH2OrderedFramesFirst;
        recvStr->mH2OrderedFramesFirst = done->mNext;
        if (!recvStr->mH2OrderedFramesFirst) {
          recvStr->mH2OrderedFramesLast = NULL;
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
#endif

static int
sdt_recv_createStream(struct SDT_RecvDataStruct_t *recvStr, uint32_t streamId)
{
  struct recvStream_t *prev = 0, *curr = recvStr->mIncomingStreams;
  while (curr && (curr->mStreamId < streamId)) {
    prev = curr;
    curr = curr->mNext;
  }
  assert(!curr || (curr->mStreamId != streamId));
  struct recvStream_t *stream =
    (struct recvStream_t*) calloc (1, sizeof(struct recvStream_t));
  if (!stream) {
    return SDTE_OUT_OF_MEMORY;
  }
  stream->mState = STREAM_IDLE;
  stream->mStreamId = streamId;
  stream->mCanSendOffset = recvStr->mInitialRwin;
  stream->mWindowSize = recvStr->mInitialRwin;
  stream->mNext = curr;

  if (!prev) {
    recvStr->mIncomingStreams = stream;
  } else {
    prev->mNext = stream;
  }
  return SDTE_OK;
}

static int
sdt_recv_removeStream(struct SDT_RecvDataStruct_t *recvStr, uint32_t streamId)
{
  struct recvStream_t *prev = 0, *curr = recvStr->mIncomingStreams;
  while (curr && (curr->mStreamId < streamId)) {
    prev = curr;
    curr = curr->mNext;
  }
  assert(curr && (curr->mStreamId == streamId));
  assert(!curr->mFrames);

  if (!prev) {
    recvStr->mIncomingStreams = curr->mNext;
  } else {
    prev->mNext = curr->mNext;
  }

  free(curr);

  return SDTE_OK;
}

static int32_t
sdt_recv_ResetStream(struct SDT_RecvDataStruct_t *recvStr, uint32_t streamId,
                     uint64_t offset, uint8_t sendRST)
{
  struct recvStream_t *stream = sdt_recv_FindStream(recvStr, streamId);

  if (!stream) {
    // this is a duplicate, just ignore it! TODO!!!!!!!!!!!!!
    return SDTE_NOT_AVAILABLE;
  }

  // App should not try to reset stream that was already reset
  assert(!(sendRST && stream->mStreamReset));

  uint64_t bytesToFree = 0;
  if (!stream->mStreamReset) {
    stream->mStreamReset = 1;
    struct recvDataFrame_t *frame = stream->mFrames;
    while (frame) {
      stream->mFrames = frame->mNext;
      bytesToFree += frame->mDataSize;
      free(frame);
      frame = stream->mFrames;
    }
  }

  if (sendRST) {
    stream->mWaitingForRSTReply = 1;

    if (stream->mState == STREAM_CLOSED) {
      // The stream has been arealy closed.
      assert(sendRST);
      bytesToFree = stream->mEndOffset - stream->mOffset;
      stream->mWaitingForRSTReply = 0;
    }
  } else {
    if (!stream->mStreamReset) {
      assert(stream->mState != STREAM_CLOSED);
#ifdef H2_MAPPING
      // Send stream->mOffset  as the final offset to look like it is a like
      // TCP reliable transport.
      int32_t rv = H2_Make_RST_STREAM(recvStr, streamId, stream->mOffset);
      if (rv) {
        return rv;
      }
#endif
    }

    if (stream->mStreamReset && !stream->mWaitingForRSTReply) {
        // This is a dup.
        assert(stream->mStreamReset && (offset == stream->mEndOffset));
        return SDTE_OK;
    }
    assert(offset >= stream->mOffset);
    assert(offset <= stream->mCanSendOffset);
    bytesToFree = offset - stream->mOffset;
    stream->mEndOffset = stream->mOffset = offset;
    stream->mWaitingForRSTReply = 0;
  }

  stream->mStreamReset = 1;
  stream->mState = STREAM_CLOSED;
  stream->mOffset += bytesToFree;
  sdt_recv_IncrementWindowForSession(recvStr, bytesToFree);

  return SDTE_OK;
}

static void
AddStreamReadyToRead(struct SDT_RecvDataStruct_t *recvStr,
                     struct sdt_t *handle,
                     struct recvStream_t *stream)
{
#ifdef H2MAPPING
  H2_OrderFramesReadyForApp(recvStr, handle, stream);
#else

  assert(stream->mFrames && (stream->mOffset == stream->mFrames->mOffset));
  assert(!stream->mNextReadyStream);

  if (recvStr->mReadyStreamsLast) {
    recvStr->mReadyStreamsLast->mNextReadyStream = stream;
  } else {
    recvStr->mReadyStreamsFirst = stream;
  }
  recvStr->mReadyStreamsLast = stream;
  recvStr->mReadyStreamsNum++;

#endif
}

static int
hOrderStreamFrame(struct SDT_RecvDataStruct_t *recvStr,
                  struct sdt_t *handle,
                  struct recvStream_t *stream, uint64_t offset, uint32_t len,
                  uint8_t finSet, const uint8_t *buf)
{
  fprintf(stderr, "hOrderStreamFrame \n");

  if (offset + len < stream->mOffset) {
    // It is a dup.
    return SDTE_OK;
  }

  uint32_t read = 0;
  // If part of the data in this packet is already send to application, ignore it.
  // This make the following code easier!
  if (offset < stream->mOffset) {
    len = len - (stream->mOffset - offset);
    read += (stream->mOffset - offset);
    offset = stream->mOffset;
  }

  struct recvDataFrame_t *prev = 0, *curr = stream->mFrames;
  while (curr && (curr->mOffset <= offset)) {
    prev = curr;
    curr = curr->mNext;
  }

  while (len) {
    if (prev &&
        ((prev->mOffset + prev->mDataSize) > offset)) {
      if (len <= (prev->mOffset + prev->mDataSize - offset)) {
        read += len;
        len = 0;
        break;
      }
      len -= (prev->mOffset + prev->mDataSize - offset);
      read += (prev->mOffset + prev->mDataSize - offset);
      offset = prev->mOffset + prev->mDataSize;
    }
    uint32_t flen = len;
    if (curr && ((offset + len) > curr->mOffset)) {
      flen = curr->mOffset - offset;
    }

    if (flen) {
      struct recvDataFrame_t *frame =
        (struct recvDataFrame_t*) malloc (sizeof(struct recvDataFrame_t) + flen);
      if (!frame) {
        return SDTE_OUT_OF_MEMORY;
      }


      frame->mNext = 0;
      frame->mOffset = offset;
      frame->mDataSize = flen;
      frame->mDataRead = 0;
      frame->mLast = 0;

      if (flen == len) {
        frame->mLast = finSet;
      }

      uint8_t *bufFrame = (uint8_t*)(frame + 1);

      memcpy(bufFrame, buf + read, flen);
      len -= flen;
      read += flen;
      offset += flen;
      frame->mNext = curr;
      if (prev) {
        prev->mNext = frame;
      } else {
        stream->mFrames = frame;
      }

      RecvFrame(stream);
      if (frame->mLast) {
        RecvFin(stream);
      }
      if (stream->mOffset == frame->mOffset) {
        AddStreamReadyToRead(recvStr, handle, stream);
      }
    }

    prev = curr;
    curr = (curr) ? curr->mNext : NULL;
  }

  assert(!len);
  return SDTE_OK;
}

static void
sdt_recv_RemoveStreamFromReadyQueue(struct SDT_RecvDataStruct_t *recvStr,
                                    struct recvStream_t *stream)
{
#ifndef H2MAPPING
  struct recvStream_t *streamP = recvStr->mReadyStreamsFirst;
  assert(streamP);
  if (streamP == stream) {
    recvStr->mReadyStreamsFirst = stream->mNextReadyStream;
    if (!recvStr->mReadyStreamsFirst) {
      recvStr->mReadyStreamsLast = NULL;
    }
  } else {
    while (streamP->mNextReadyStream && (streamP->mNextReadyStream != stream)) {
      streamP = streamP->mNextReadyStream;
    }

    assert(streamP->mNextReadyStream);

    streamP->mNextReadyStream = stream->mNextReadyStream;

    if (stream == recvStr->mReadyStreamsLast) {
      recvStr->mReadyStreamsLast = streamP;
    }
  }

  stream->mNextReadyStream = NULL;
  recvStr->mReadyStreamsNum--;
#endif
}

static int
Received_STREAM_FRAME(struct SDT_RecvDataStruct_t *recvStr,
                      struct sdt_t *handle, uint32_t streamId,
                      uint64_t offset, uint16_t len, uint8_t finSet,
                      const uint8_t *buf)
{
  // First ensure that if this is a new remote stream that it has been created.
  int32_t rv = sdt_EnsureStreamCreated(handle, streamId);
  if (rv) {
    return rv;
  }
  struct recvStream_t *stream = sdt_recv_FindStream(recvStr, streamId);

  // If there is no stream, that means that the stream has been closed.
  if (!stream) {
    return SDTE_STREAM_DELETED;
  }

  assert((offset + len) <= stream->mCanSendOffset);

  if (stream->mState == STREAM_CLOSED) {
    if (stream->mWaitingForRSTReply) {
      assert(stream->mStreamReset);
      if (finSet) {
        stream->mEndOffset = offset + len;
        stream->mWaitingForRSTReply = 0;
        assert(stream->mEndOffset >= stream->mOffset);
        sdt_recv_IncrementWindowForSession(recvStr,
                                           stream->mEndOffset - stream->mOffset);
      }
    } else {
      // We ave received RST or FIN so be sure to check:
      if ((offset +len) > stream->mEndOffset) {
        // TODO GO_AWAY with error!!!
        return SDTE_FATAL_ERROR;
      }
    }

    if (stream->mStreamReset) {
      // Ignore the packet.
      return SDTE_OK;
    }
  } else if (finSet) {
    stream->mEndOffset = offset + len;
    stream->mState = STREAM_CLOSED;
  }

  return hOrderStreamFrame(recvStr, handle, stream, offset, len, finSet, buf);
}

#ifndef H2MAPPING
static int
SDT_Recv(struct SDT_RecvDataStruct_t *recvStr, void *buf, int32_t amount,
         int flags, uint8_t tlsHandshake)
{
  assert(recvStr->mNextToReadSet || tlsHandshake || (flags & PR_MSG_PEEK));
  recvStr->mNextToReadSet = 0;

  struct recvStream_t *stream = sdt_recv_FindStream(recvStr,
                                                    recvStr->mNextToReadId);

//TODO
  if (!stream) {
    return -1;
  }

  // Assert that we have the needed stream and that that stream is not reset.
  assert(stream &&
         !((stream->mState == STREAM_CLOSED) && stream->mStreamReset));

  if (!stream->mFrames ||
      (stream->mOffset != (stream->mFrames->mOffset + stream->mFrames->mDataRead))) {

    // DEBUG
    struct recvStream_t *streamP = recvStr->mReadyStreamsFirst;
    while (streamP && streamP != stream) {
      streamP = streamP->mNext;
    }
    assert(!streamP);
    // End DEBUG

    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  // Making it so complecated because of PR_MSG_PEEK.
  struct recvDataFrame_t *frame = stream->mFrames;
  uint32_t frameSize = frame->mDataSize;
  uint32_t frameAlreadyRead = frame->mDataRead;
  uint32_t nextOffset = stream->mOffset;
  int32_t read = 0;
  while ((read < amount) && frame) {
    uint8_t *framebuf = (uint8_t*)(frame + 1);
    int32_t toRead = frameSize - frameAlreadyRead;
    toRead = (toRead > (amount - read)) ? (amount - read) : toRead;
    memcpy(((uint8_t *)buf) + read,
           framebuf + frameAlreadyRead,
           toRead);
    read += toRead;
    if (!(flags & PR_MSG_PEEK)) {
      frame->mDataRead += toRead;
      stream->mOffset += toRead;
    }
    frameAlreadyRead += toRead;
    nextOffset += toRead;
    if (frameAlreadyRead == frameSize) {
      frame = frame->mNext;
      // If the next one is not the next in row, do not read it!!!
      if (frame && (frame->mOffset != nextOffset)) {
        frame = NULL;
      }
      if (frame) {
        frameSize = frame->mDataSize;
        frameAlreadyRead = frame->mDataRead;
      }
      if (!(flags & PR_MSG_PEEK)) {
        struct recvDataFrame_t *done = stream->mFrames;
        stream->mFrames = done->mNext;
        if (!stream->mFrames || (stream->mOffset != stream->mFrames->mOffset)) {
          sdt_recv_RemoveStreamFromReadyQueue(recvStr, stream);
        }
        free(done);
      }
    }
  }

  if (!(flags & PR_MSG_PEEK)) {
    sdt_recv_IncrementWindowForSession(recvStr, read);
    sdt_recv_IncrementWindowForStream(recvStr, stream, read);
  }

  if (!read) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  return read;
}
#endif

static int
Received_WINDOW_UPDATE(struct SDT_RecvDataStruct_t *recvStr, uint32_t streamId,
                       uint64_t offset)
{
  if (streamId == 0) {
    if (recvStr->mSendStr->mCanSendSessionOffset >= offset) {
      // ignore if the offset is smaller then mCanSendSessionOffset.
      fprintf(stderr, "Old windows update current win=%lu offset= %lu\n",
              recvStr->mSendStr->mCanSendSessionOffset, offset);
      return SDTE_OK;
    }

#ifdef H2MAPPING
    int rv = H2_Make_WINDOW_UPDATE(recvStr, streamId,
                                   offset - recvStr->mSendStr->mCanSendSessionOffset);
    if (rv) {
      return rv;
    }
#endif

    recvStr->mSendStr->mCanSendSessionOffset = offset;
  } else {

    struct aOutgoingStreamInfo_t *streamInfo =
      sdt_send_FindStream(recvStr->mSendStr, streamId);

    // TODO: dragana take a look at this!
    if (!streamInfo) {
      // ignore
      fprintf(stderr, "No record for stream %d\n", streamId);
      return SDTE_OK;
    }

    if (offset <= streamInfo->mCanSendOffset) {
      // ignore if the offset is smaller then mCanSendOffset.
      fprintf(stderr, "Old windows update current win=%lu offset= %lu\n",
              streamInfo->mCanSendOffset, offset);
      return SDTE_OK;
    }

#ifdef H2MAPPING
    if (streamId != 1) {
      int rv = H2_Make_WINDOW_UPDATE(recvStr, streamId,
                                     offset - streamInfo->mCanSendOffset);
      if (rv) {
        return rv;
      }
    }
#endif
    streamInfo->mCanSendOffset = offset;
  }
  return SDTE_OK;
}

struct sdt_t
{
  uint64_t connectionId; // session identifier for mobility. TODO not used now.
  uint8_t publicHeaderLen;
  uint16_t payloadsize;
  uint16_t cleartextpayloadsize;

  PRNetAddr peer;
  uint8_t isConnected;
  uint8_t isServer;

  enum SDTConnectionState state;

  uint64_t aLargestAcked;
  uint64_t aSmallestUnacked;

  struct range_t *aRecvAckRange; // We are keeping track of the ack ranges that
                                 // a sender has already received from the
                                 // receiver. So we can search
                                 // mSDTSendDataStr only for a diff.
                                 // These are actually ACKed(SACK) ranges not
                                 // NACKed!!! (easier to compare, even though
                                 // we get NACK ranges in an ACK)

  // TODO add this.
  // Let's keep track of acks so that we do not need to go though
  // mSDTSendDataStr for nacked acks. They are not in queue so that will
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
  uint64_t aLargestRecvId;
  PRIntervalTime aLargestRecvTime;
  uint8_t aNumTimestamps;
  uint64_t aTSSeqNums[NUMBER_OF_TIMESTAMPS_STORED];
  // TODO we can also get rtt for acks, currently partially implemented. Acks
  // have different pkt size, maybe it is useful. (if we do not need it is easy
  // to remove it)
  // We keep last NUMBER_OF_TIMESTAMPS_STORED timestamps and this is array is
  // used as a ring.
  // aNumTimestamps is used as the number of timestamps and as the index where
  // the next timestamp should be written. Therefore, if we have less than
  // NUMBER_OF_TIMESTAMPS_STORED timestamps, aNumTimestamps is the real number
  // of timestamps. If we have NUMBER_OF_TIMESTAMPS_STORED timestamps,
  // aNumTimestamps is between NUMBER_OF_TIMESTAMPS_STORED and
  // 2*NUMBER_OF_TIMESTAMPS_STORED
  PRIntervalTime aTimestamps[NUMBER_OF_TIMESTAMPS_STORED];

  // Not acked packet ranges. They will be sent in an ACK.
  struct range_t *aNackRange;
  // This is a flag that tell us that we need to send an ACK.
  uint8_t aNeedAck;

  PRIntervalTime aNextToRetransmit;

  // RTT parameter neede for RTT and RTO calculation.
  PRIntervalTime srtt;
  PRIntervalTime rttvar;
  PRIntervalTime minrtt;
  PRIntervalTime rto;
  uint8_t waitForFirstAck;

  PRIntervalTime RTOTimer; // TODO: this is not really a timer, it is check during poll.
  uint8_t RTOTimerSet;

  PRIntervalTime ERTimer; // TODO: the same as RTOTimer
  uint8_t ERTimerSet;

  // This is for pacing - currently not implemented.
  PRTime qLastCredit;
  // credits are key in ums
  uint64_t qCredits;
  uint64_t qMaxCredits;
  uint64_t qPacingRate;

#ifdef H2MAPPING
  // When we receive H2 frame we store header infos in the following variables.
  // They are decoded in the decodeH2Header and DecodeH2Frames function.
  uint8_t hType;
  uint8_t hFlags;
  uint16_t hDataLen;
  uint32_t hH2StreamId;
  uint32_t hSDTStreamId;
  uint8_t hPadding;
  struct aDataChunk_t *hCurrentDataChunk;
  enum SDTH2SState hState;
  uint8_t hMagicHello;
#endif

  struct SDT_SendDataStruct_t mSDTSendDataStr;

  struct SDT_RecvDataStruct_t mSDTRecvDataStr;

  uint8_t numOfRTORetrans;

  PRFileDesc *fd; // weak ptr, don't close

  uint64_t aNextPacketId;
  uint64_t mNextStreamIdLocal;
  uint64_t mNextStreamIdRemote;

  // The congestion control parameters.
  struct sdt_cc_t ccData;
};

struct sdt_t *
sdt_newHandle(uint8_t server)
{
  struct sdt_t *handle = (struct sdt_t *) calloc (1, sizeof(struct sdt_t));

  if (!handle) {
    return NULL;
  }

  handle->isServer = server;
  handle->publicHeaderLen = 1 + 8; // connectionId nad packetId
  handle->payloadsize = SDT_PAYLOADSIZE_MAX - 1;
  handle->cleartextpayloadsize = SDT_CLEARTEXTPAYLOADSIZE_MAX - handle->publicHeaderLen;

  handle->state = SDT_CONNECTING;

  handle->mSDTSendDataStr.mCanSendSessionOffset = aBufferLenMax;
  handle->mSDTSendDataStr.mServerInitialStreamWindow = DEFAULTE_RWIN;
  handle->mSDTRecvDataStr.mSendStr = &handle->mSDTSendDataStr;
  handle->mSDTRecvDataStr.mInitialRwin = DEFAULTE_RWIN;
  handle->mSDTRecvDataStr.mCanSendSessionOffset = aBufferLenMax;

  handle->aNextToRetransmit = 0xffffffffUL;

  handle->rto = sMinRTO;
  handle->numOfRTORetrans = 0;
  handle->waitForFirstAck = 1;

  handle->qMaxCredits = qMaxCreditsDefault;
  handle->qMaxCredits = qPacingRateDefault * 3; // TODO: not use currently
  handle->qPacingRate = qPacingRateDefault;

#ifdef H2MAPPING
  handle->hState = SDT_H2S_NEWFRAME;
#endif

  handle->aNextPacketId = 1;
  handle->mNextStreamIdLocal = (server) ? 2 : 3;
  handle->mNextStreamIdRemote = (server) ? 3 : 2;

  cc->Init(&handle->ccData);

  return handle;
}

static void
sdt_freeHandle(struct sdt_t *handle)
{
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

  ClearSDTSendDataStr(&handle->mSDTSendDataStr);

  ClearSDTRecvDataStr(&handle->mSDTRecvDataStr);

  free(handle);
}

int32_t
sdt_CreateStream(struct sdt_t *handle, uint32_t *streamId)
{
  assert(streamId);

  assert(handle->mNextStreamIdLocal);
  int32_t rv = sdt_send_createStream(&handle->mSDTSendDataStr,
                                     handle->mNextStreamIdLocal);

  if (rv) {
    return rv;
  }

  rv = sdt_recv_createStream(&handle->mSDTRecvDataStr,
                             handle->mNextStreamIdLocal);
  if (rv) {
     sdt_send_removeStream(&handle->mSDTSendDataStr,
                           handle->mNextStreamIdLocal);
    return rv;
  }
  *streamId = handle->mNextStreamIdLocal;
  handle->mNextStreamIdLocal += 2;
  return SDTE_OK;
}

int32_t
sdt_EnsureRemoteStreamCreated(struct sdt_t *handle, uint32_t streamId)
{
  // Assert that this is remote streamId;
  assert((streamId & 1) == handle->isServer);
  while (handle->mNextStreamIdRemote &&
         (handle->mNextStreamIdRemote <= streamId)) {
    int32_t rv = sdt_send_createStream(&handle->mSDTSendDataStr,
                                       handle->mNextStreamIdRemote);
    if (rv) {
      return rv;
    }

    rv = sdt_recv_createStream(&handle->mSDTRecvDataStr,
                               handle->mNextStreamIdRemote);
    if (rv) {
      sdt_send_removeStream(&handle->mSDTSendDataStr,
                            handle->mNextStreamIdRemote);
      return rv;
    }
    handle->mNextStreamIdRemote += 2;
  }
  return SDTE_OK;
}

int32_t
sdt_EnsureStreamCreated(struct sdt_t *handle, uint32_t streamId)
{
  int32_t rv = SDTE_OK;

  if ((streamId & (uint32_t)0x1) != handle->isServer) {
    // It is localy opened stream!!!
    assert(!handle->mNextStreamIdLocal ||
           (handle->mNextStreamIdLocal > streamId));
  } else {
    rv = sdt_EnsureRemoteStreamCreated(handle, streamId);
  }
  return rv;
}

int32_t
sdt_LocalCloseStream(struct sdt_t *handle, uint32_t streamId)
{
  assert(streamId);

  return sdt_send_CloseStream(&handle->mSDTSendDataStr, streamId);
}

int32_t
sdt_ResetStream_Internal(struct sdt_t *handle, uint32_t streamId,
                         uint64_t offset, uint8_t sendRST)
{
  assert(streamId);

  if (sendRST) {
    if ((streamId & 1) != handle->isServer) {
      // It is localy opened stream!!!
      assert(!handle->mNextStreamIdLocal ||
             (handle->mNextStreamIdLocal > streamId));
    } else {
      // It is remote opened stream!!!
      assert(!handle->mNextStreamIdRemote ||
             (handle->mNextStreamIdRemote > streamId));
    }
  } else {
    if ((streamId & 1) != handle->isServer) {
      // It is localy opened stream!!!
      assert(!handle->mNextStreamIdLocal ||
             (handle->mNextStreamIdLocal > streamId));
    } else {
      // It can be that some pakets are reordered or lost so we have not
      // received some frames that hd opened new streams. We need to open them
      // now.
      int32_t rv = sdt_EnsureRemoteStreamCreated(handle, streamId);
      if (rv) {
        return rv;
      }
    }
  }

  int32_t rv = sdt_send_ResetStream(&handle->mSDTSendDataStr, streamId,
                                    sendRST);
  if (rv) {
    return rv;
  }

  return sdt_recv_ResetStream(&handle->mSDTRecvDataStr, streamId, offset,
                              sendRST);
}

static unsigned int
sdt_preprocess(struct sdt_t *handle, unsigned char *pkt, uint32_t len)
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

//==============================================================================
// Decoding and encoding sLayer packets.
// sLayer reads packet sequence number and uses it to mark packer as received.
//==============================================================================

static int32_t
sLayerPacketReceived(struct sdt_t *handle, uint16_t epoch, uint64_t seq,
                     uint8_t *newPkt)
{
  *newPkt = 0;

  fprintf(stderr, "%d sLayerPacketReceived largest receive till now=%lu; this "
          "packet seq=%lu handle=%p\n",
          PR_IntervalNow(), handle->aLargestRecvId, seq, (void *)handle);

  PRIntervalTime now = PR_IntervalNow();

  if (handle->aLargestRecvId < seq) {
    if ((handle->aLargestRecvId + 1) < seq) {

      // there is some packets missing between last largest and the new largest
      // packet id.
      struct range_t *range =
        (struct range_t *) malloc (sizeof(struct range_t));
      if (!range) {
        return SDTE_OUT_OF_MEMORY;
      }
      range->mStart = handle->aLargestRecvId + 1;
      range->mEnd = seq - 1;
      range->mNext = handle->aNackRange;
      handle->aNackRange = range;
    }
    handle->aLargestRecvId = seq;
    handle->aLargestRecvTime = now;
    *newPkt = 1;

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
      *newPkt = 0;

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
        if (!newRange) {
          return SDTE_OUT_OF_MEMORY;
        }
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

      *newPkt = 1;
    }
  }
  if (*newPkt) {
    int inx = handle->aNumTimestamps % NUMBER_OF_TIMESTAMPS_STORED;
    handle->aTSSeqNums[inx] = seq;
    handle->aTimestamps[inx] = now;
    handle->aNumTimestamps++;
    if (handle->aNumTimestamps == (NUMBER_OF_TIMESTAMPS_STORED << 2)) {
     handle->aNumTimestamps = NUMBER_OF_TIMESTAMPS_STORED;
    }
  }
  return 0;
}

/**
 *
 *  +--------+
 *  |Flags   |
 *  +--------+--------+--------+--------+--    --+
 *  |ConnectionId (0, 8, 32 or 64)         ...   |
 *  +--------+--------+--------+--------+--    --+
 *  |Packet id (32)                     |
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

  memmove(buf, buf + handle->publicHeaderLen, amount - handle->publicHeaderLen);
  LogBuffer("To decode: ", buf, amount-handle->publicHeaderLen);
  return amount - handle->publicHeaderLen;
}

static uint32_t
sLayerEncodePublicContent(struct sdt_t *handle, const void *buf,
                          int32_t amount)
{
  // this is a quick change to make sdt work with dtls. In the second phase I
  // will adapt tls

  LogBuffer("To encode: ", buf, amount);
  memcpy(handle->sLayerSendBuffer + handle->publicHeaderLen, buf, amount);
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

  return amount + handle->publicHeaderLen;
}

//==============================================================================

static int32_t
sLayerRecv(PRFileDesc *fd, void *buf, int32_t amount,
           int flags, PRIntervalTime to)
{
  int32_t recvRv = fd->lower->methods->recv(fd->lower, buf, amount, flags, to);

  if (recvRv < 0) {
    return recvRv;
  }

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

  handle->sBytesRead += recvRv;

  recvRv = sLayerDecodePublicContent(handle, buf, recvRv);

  if (!sdt_preprocess(handle, buf, recvRv)) {
    assert(0);
    return -1;
  }

  fprintf(stderr," %dsLayer Recv got %d of ciphertext this=%p "
          "type=%d epoch=%X seq=0x%lX dtlsLen=%d sBytesRead=%ld sRecvPktId:%ld\n",
          PR_IntervalNow(), recvRv, (void *)handle,
          handle->sRecvRecordType, handle->sRecvEpoch, handle->sRecvSeq,
          handle->sRecvDtlsLen, handle->sBytesRead, handle->sRecvPktId);

  if (handle->sRecvPktId != 0) {
    uint8_t newPkt = 0;
    int32_t rv = sLayerPacketReceived(handle, 0, handle->sRecvPktId, &newPkt);
    if (rv) {
      return rv;
    }
    if (!newPkt) {
      PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
      return -1;
    }
  }
  return recvRv;
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

  uint32_t dataLen = sLayerEncodePublicContent(handle, buf, amount);

  int rv = fd->lower->methods->sendto(fd->lower, handle->sLayerSendBuffer,
                                      dataLen, flags, addr, to);

  fprintf(stderr,"%d sLayer send %p %d rv=%d\n", PR_IntervalNow(),
          (void *)handle, amount, rv);

  if (rv <= 0) {
    return rv;
  }

  if (rv != (int32_t)dataLen) {
    DEV_ABORT();
    // todo set err
    return -1;
  }

  if ((((uint8_t*)buf)[0]) != DTLS_TYPE_DATA) {
    // It is a DTLS handshake packet.
    return amount;
  }

  if (PacketNeedAck(&handle->mSDTSendDataStr)) {
    cc->OnPacketSent(&handle->ccData, handle->aNextPacketId, rv);
  }

  handle->aNextPacketId++;
  return amount;
}

static uint8_t
DoWeNeedToSendAck(struct sdt_t *handle)
{
  // TODO: Decide when we are going to send ack, for each new packet probably,
  // but maybe implement delayACK as well.
  return handle->aNeedAck;
}

static void
MakeAckPkt(struct sdt_t *handle, struct aPacket_t *pkt)
{
  // TODO: For now we are always sanding as much as it can fit in a pkt.
  // To fix:
  // 1) Make possible to send multiple packets if the ack info does not fit
  //    into one.
  // 2) implement STOP_WAITING
  // 3) if number of consecutive lost packet exceed 256, current implementation
  //    will fail. make continues ranges.

  unsigned char *buf = (unsigned char *)(pkt + 1);

  buf[0] = 0x40;
  buf[1] = 0;
  uint64_t num64 = htonll(handle->aLargestRecvId);

  memcpy(buf + 2, &num64, 8);
  // TODO: fix this. (hint: largestReceived time delta)
  uint32_t num32 = htonl(PR_IntervalToMicroseconds(PR_IntervalNow() -
                         handle->aLargestRecvTime));
  memcpy(buf + 10, &num32, 4);
  uint8_t numTS = 0;
  pkt->mWritten += 15;
  int i = handle->aNumTimestamps - 1;
  int prevInx = 0;
  for (; i >= 0 && i >= handle->aNumTimestamps - NUMBER_OF_TIMESTAMPS_STORED; i--) {
    int inx = i % NUMBER_OF_TIMESTAMPS_STORED;
    if ((handle->aLargestRecvId - handle->aTSSeqNums[inx]) < 255) {
      buf[pkt->mWritten] = (uint8_t)(handle->aLargestRecvId - handle->aTSSeqNums[inx]);
      pkt->mWritten++;
      if (!numTS) {
        num32 = htonl(PR_IntervalToMicroseconds(PR_IntervalNow() -
                                                handle->aTimestamps[inx]));
      } else {
        num32 = htonl(PR_IntervalToMicroseconds(handle->aTimestamps[prevInx] -
                                                handle->aTimestamps[inx]));
      }
//fprintf(stderr, "MakeAck last %d %d %d %d %d %d\n", handle->aLargestRecvId, handle->aTSSeqNums[inx], ntohl(num32), i, handle->aNumTimeStamps, numTS);
      memcpy(buf + pkt->mWritten, &num32, 4);
      pkt->mWritten += 4;
      prevInx = inx;
      numTS++;
    }
  }
  buf[14] = numTS;
  uint8_t numR = 0;
  if (handle->aNackRange) {
    uint32_t offsetRangeNum = pkt->mWritten;
    pkt->mWritten++;
    buf[0] = 0x60;
    struct range_t *curr = handle->aNackRange;
    struct range_t *prev = NULL;
    uint32_t continuesLeft = 0;
    while (curr && (pkt->mWritten < (pkt->mSize - 9))) {
      if (!numR) {
        num64 = htonll(handle->aLargestRecvId - curr->mEnd);
      } else if (!continuesLeft) {
        num64 = htonll(prev->mStart - curr->mEnd - 1);
      } else {
        num64 = 0;
      }
//fprintf(stderr, "MakeAck range %lu %lu\n", curr->mStart, curr->mEnd);
      memcpy(buf + pkt->mWritten, &num64, 8);
      pkt->mWritten += 8;
      uint64_t rangeLength = (!continuesLeft) ? curr->mEnd - curr->mStart :
                                                continuesLeft;
      if (rangeLength > 256) {
        buf[pkt->mWritten] = 255;
        continuesLeft = rangeLength - 256;
      } else {
        buf[pkt->mWritten] = (uint8_t)(rangeLength);
        prev = curr;
        curr = curr->mNext;
      }
      numR++;
      pkt->mWritten++;
    }
    buf[offsetRangeNum] = numR;
  }
  handle->aNeedAck = 0;
}

// r is timeRecv - timeSent and delay is delay at receiver
// srtt uses r and minrtt uses clean rtt r - delay. minrtt still not used,
// maybe not needed, it is from quic.
static void
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

static void
MaybeStartRTOTimer(struct sdt_t *handle)
{
  if (!handle->RTOTimerSet) {
    handle->RTOTimerSet = 1;
    handle->RTOTimer = PR_IntervalNow() + handle->rto;
  }
}

static void
StopRTOTimer(struct sdt_t *handle)
{
  handle->RTOTimerSet = 0;
}

static void
RestartRTOTimer(struct sdt_t *handle)
{
  assert(handle->RTOTimerSet);
  handle->RTOTimer = PR_IntervalNow() + handle->rto;
}

static uint8_t
RTOTimerExpired(struct sdt_t *handle, PRIntervalTime now)
{
  return (handle->RTOTimerSet && (handle->RTOTimer < now));
}

static void
StartERTimer(struct sdt_t *handle)
{
  handle->ERTimerSet = 1;
  handle->ERTimer = PR_IntervalNow() + handle->srtt * EARLY_RETRANSMIT_FACTOR;
}

static uint8_t
ERTimerExpired(struct sdt_t *handle, PRIntervalTime now)
{
  return (handle->ERTimerSet && (handle->ERTimer < now));
}

static void
StopERTimer(struct sdt_t *handle)
{
  handle->ERTimerSet = 0;
}

static int8_t
NeedToSendRetransmit(struct sdt_t *handle)
{
  PRIntervalTime now = PR_IntervalNow();
  return RTOTimerExpired(handle, now) ||
         ERTimerExpired(handle, now);
}

struct aAckedPacket_t
{
  uint64_t mId;
  uint32_t mSize;
  PRIntervalTime mRtt;
  uint8_t mHasRtt;
  struct aAckedPacket_t* mNext;
};

static int
RemoveAckedRange(struct sdt_t *handle, uint64_t end, uint64_t start, int numTS,
                 uint32_t *tsDelay, uint64_t *tsSeqno,
                 struct aAckedPacket_t **ackedFirst,
                 struct aAckedPacket_t **ackedLast)
{
  // This function removes range of newly acked packets and updates rtt, rto.

  assert(end >= start);
  // TODO keep track of ACK packets. Because acks are not in retransmission
  // queue search will need to through the whole queue.

  struct aPacketInfo_t *pkt = NULL;
  for (uint64_t i = start; i <= end; i++) {
    pkt = PacketAcked(&handle->mSDTSendDataStr, i);

    // We are also acking acks so maybe there is no pkt
    if (pkt) {
      // Currently the max numTS is NUMBER_OF_TIMESTAMPS_STORED,
      // TODO: this can be optimize by preprocessing tsDelay and tsSeqno. We
      // should get timestamps only for non acked packet.
      int ts = 0;
      PRIntervalTime rtt = 0;
      uint8_t hasRtt = 0;
      while (!rtt && ts < numTS) {
        // Use this measurement only if delay is not greater than rtt.
        if ((tsDelay[ts] < handle->srtt) || !handle->srtt) {
          if (pkt->mPacketSeqNum == tsSeqno[ts]) {
            rtt = PR_IntervalNow() - pkt->mSentTime;
            hasRtt = 1;
            CalculateRTT(handle,
                         PR_IntervalNow() - pkt->mSentTime,
                         tsDelay[ts]);
            break;
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
      ack->mSize = pkt->mSize + DTLS_PART + handle->publicHeaderLen;
      ack->mRtt = rtt;
      ack->mHasRtt = hasRtt;
      ack->mNext = NULL;
      if (!*ackedFirst) {
        *ackedLast = *ackedFirst = ack;
      } else {
        (*ackedLast)->mNext = ack;
        *ackedLast = ack;
      }

#ifdef H2MAPPING
      if (pkt->mIsPingPkt) {
        int rc = H2_Make_PING_ACK(&handle->mSDTRecvDataStr);
        if (rc) {
          goto cleanup;
        }

      }
#endif
      free(pkt);
    }
  }

  return 0;

  cleanup:
  free(pkt);
  return SDTE_OUT_OF_MEMORY;
}


static void
NeedRetransmissionDupAck(struct sdt_t *handle)
{
  while (handle->mSDTSendDataStr.mSentPacketInfo.mFirst &&
         (handle->mSDTSendDataStr.mSentPacketInfo.mFirst->mPacketSeqNum <= handle->aLargestAcked)) {

    cc->OnPacketLost(&handle->ccData,
                     handle->mSDTSendDataStr.mSentPacketInfo.mFirst->mPacketSeqNum,
                     handle->mSDTSendDataStr.mSentPacketInfo.mFirst->mSize);
    assert(MarkPacketLost(&handle->mSDTSendDataStr,
           handle->mSDTSendDataStr.mSentPacketInfo.mFirst));
  }
}

static int
RecvAck(struct sdt_t *handle)
{
  fprintf(stderr, "RecvAck [this=%p]\n", (void *)handle);

  assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= 16);

  // If we have a loss reported in the packet, we need to call OnPacketLost
  // before calling OnPacketAcked, because of a cwnd calculation.
  struct aAckedPacket_t *newlyAckedFirst = 0;
  struct aAckedPacket_t *newlyAckedLast = 0;
  int rc = SDTE_OK;

  uint8_t type = handle->aLayerBuffer[handle->aLayerBufferUsed];
  handle->aLayerBufferUsed++;
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

    rc = RemoveAckedRange(handle, largestRecv, handle->aLargestAcked + 1,
                          numTS, tsDelay, tsSeqno, &newlyAckedFirst, &newlyAckedLast);
    if (rc) {
      goto cleanup;
    }

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
      if (!curr) {
        rc = SDTE_OUT_OF_MEMORY;
        goto cleanup;
      }
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
        rc = RemoveAckedRange(handle, newRanges[i].mStart,
                              newRanges[i].mEnd, numTS, tsDelay, tsSeqno,
                              &newlyAckedFirst, &newlyAckedLast);
        if (rc) {
          goto cleanup;
        }

        struct range_t *newRange =
          (struct range_t *) malloc (sizeof(struct range_t));
        if (!newRange) {
          rc = SDTE_OUT_OF_MEMORY;
          goto cleanup;
        }
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
          rc = RemoveAckedRange(handle, newRanges[i].mStart, curr->mStart,
                                numTS, tsDelay, tsSeqno,
                                &newlyAckedFirst, &newlyAckedLast);
          if (rc) {
            goto cleanup;
          }
          curr->mStart = newRanges[i].mStart;
        }

        if (newRanges[i].mEnd < curr->mEnd) {
          struct range_t *nextR = curr->mNext;
          assert(nextR); // The last one ends at 0 so this
          while (newRanges[i].mEnd < nextR->mEnd) {

            if (nextR->mStart > newRanges[i].mEnd) {
              // merge 2 ranges
              rc = RemoveAckedRange(handle, curr->mEnd, nextR->mStart,
                                    numTS, tsDelay, tsSeqno,
                                    &newlyAckedFirst, &newlyAckedLast);
              if (rc) {
                goto cleanup;
              }

              curr->mEnd =  nextR->mEnd;
              curr->mNext = nextR->mNext;
              free(nextR);
            }
          }
        }
        if (newRanges[i].mEnd < curr->mEnd) {
          rc = RemoveAckedRange(handle, curr->mEnd, newRanges[i].mEnd,
                                numTS, tsDelay, tsSeqno,
                                &newlyAckedFirst, &newlyAckedLast);
          if (rc) {
            goto cleanup;
          }

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

  if (newlyAckedFirst) {
    NeedRetransmissionDupAck(handle);

    uint64_t oldSmallestUnacked = handle->aSmallestUnacked;
    if (!sdt_send_HasUnackedPackets(&handle->mSDTSendDataStr)) {
      // All packets are acked stop RTO timer.
      StopRTOTimer(handle);
      StopERTimer(handle);
      handle->aSmallestUnacked = handle->aLargestAcked + 1;
    } else {
      // Some new packet(s) are acked and we have outstanding packets - restart
      // rto timer.
      RestartRTOTimer(handle);
      if (hasRanges) {
        //TODO: dragana check this.
        handle->aSmallestUnacked = sdt_send_SmallestPktSeqNumNotAcked(&handle->mSDTSendDataStr);
      } else {
        handle->aSmallestUnacked = handle->aLargestAcked;
      }
    }

    if (hasRanges && oldSmallestUnacked < handle->aSmallestUnacked) {
      // Send Stop waiting!
      // Maybe send stop waiting only if a whole range is asked.
      // also after e.g. 2 retransmissions.
    }
    while (newlyAckedFirst) {
      struct aAckedPacket_t *curr = newlyAckedFirst;
      newlyAckedFirst = newlyAckedFirst->mNext;
      cc->OnPacketAcked(&handle->ccData, curr->mId,
                        handle->aSmallestUnacked,
                        curr->mSize, curr->mRtt, curr->mHasRtt);
      free(curr);
    }
  }

  if ((sdt_send_HasDataForTransmission(&handle->mSDTSendDataStr)) &&
      (handle->aLargestSentId == handle->aLargestAcked)) {
    StartERTimer(handle);
  }
  return SDTE_OK;

  cleanup:
  while (newlyAckedFirst) {
    struct aAckedPacket_t *curr = newlyAckedFirst;
    newlyAckedFirst = newlyAckedFirst->mNext;
    free(curr);
  }
  return rc;
}

static void
CheckRetransmissionTimers(struct sdt_t *handle)
{
  if (ERTimerExpired(handle, PR_IntervalNow())) {
    fprintf(stderr, "ERTimerExpired\n");
    assert(handle->mSDTSendDataStr.mSentPacketInfo.mFirst);
    struct aPacketInfo_t *pkt = handle->mSDTSendDataStr.mSentPacketInfo.mFirst;
    cc->OnPacketLost(&handle->ccData, pkt->mPacketSeqNum, pkt->mSize);
    MarkPacketLost(&handle->mSDTSendDataStr, pkt);

    StopERTimer(handle);

  } else if (RTOTimerExpired(handle, PR_IntervalNow())) {
    fprintf(stderr, "RTOTimerExpired\n");
    assert(handle->mSDTSendDataStr.mSentPacketInfo.mFirst);
    struct aPacketInfo_t *pkt = handle->mSDTSendDataStr.mSentPacketInfo.mFirst;
    // Mare all for retransmission.
    while (pkt) {
      MarkPacketLost(&handle->mSDTSendDataStr, pkt);
      pkt = handle->mSDTSendDataStr.mSentPacketInfo.mFirst;
    }
    handle->rto *= 2;
    handle->numOfRTORetrans++;
    cc->OnRetransmissionTimeout(&handle->ccData);
    // This is a bit incorrect, but it is ok. We  should restart it when we do
    // resend this pkt.
    RestartRTOTimer(handle);
  }
}

static int
sdt_DecodeFrames(struct sdt_t *handle)
{
  LogBuffer("sdt_DecodeFrames buffer ", handle->aLayerBuffer,
            handle->aLayerBufferLen );

  while (handle->aLayerBufferLen > handle->aLayerBufferUsed) {
    uint8_t type = handle->aLayerBuffer[handle->aLayerBufferUsed];
    if (type & SDT_FRAME_TYPE_STREAM) {
      fprintf(stderr, "SDT_SDT_FRAME_TYPE_STREAM received\n");
      // This is a stream frame.
      handle->aNeedAck = 1;

      uint32_t streamId = 0;
      uint8_t streamIdLen = 0;
      uint64_t offset = 0;
      uint8_t offsetLen = 0;
      uint8_t fin = 0;
      uint16_t frameLen = 0;

      int32_t read = sdt_decode_StreamFrame(handle->aLayerBuffer + handle->aLayerBufferUsed,
                                            handle->aLayerBufferLen - handle->aLayerBufferUsed,
                                            &streamId, &streamIdLen,
                                            &offset, &offsetLen,
                                            &fin, &frameLen);
      if (read < 0) {
        return read;
      }
      handle->aLayerBufferUsed += read;

      // For now TODO
      assert(streamIdLen == 4);
      assert((offsetLen == 8) || (offsetLen == 0));

      int rc = Received_STREAM_FRAME(&handle->mSDTRecvDataStr, handle, streamId,
                                     offset, frameLen, fin,
                                     handle->aLayerBuffer + handle->aLayerBufferUsed);
      if (rc < 0) {
        return rc;
      }

      handle->aLayerBufferUsed += frameLen;

    } else if (type & SDT_FRAME_TYPE_ACK) {
      // This is an ACK frame.
      fprintf(stderr, "SDT_FRAME_TYPE_ACK received\n");
      int rc = RecvAck(handle);
      if (rc)
        return rc;
    } else if (type & SDT_FRAME_TYPE_CONGESTION_FEEDBACK) {
      // This is CONGESTION_FEEDBACK.
      // Currently not implemented, ignore frame.
      // I assume it has only type field.
      fprintf(stderr, "SDT_FRAME_TYPE_STOP_CONGESTION_FEEDBACK received.\n");
      handle->aLayerBufferUsed++;
      handle->aNeedAck = 1;
    } else {
      handle->aNeedAck = 1;
      handle->aLayerBufferUsed++; // frame type byte.
      switch (type) {
        case SDT_FRAME_TYPE_PADDING:
          // Ignore 0x0 bytes.
          fprintf(stderr, "SDT_FRAME_TYPE_PADDING received.\n");
          while ((handle->aLayerBufferLen >= handle->aLayerBufferUsed) &&
                 handle->aLayerBuffer[handle->aLayerBufferUsed] == 0) {
            handle->aLayerBufferUsed++;
          }
          handle->aLayerBufferLen = 0;
          break;
        case SDT_FRAME_TYPE_RST_STREAM:
          {
            fprintf(stderr, "SDT_FRAME_TYPE_RST_STREAM received.\n");
            assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >=
                   (4 + 8 + 4));

            uint32_t error;
            memcpy(&error, handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            error = ntohl(error);
            handle->aLayerBufferUsed += 4;

            uint32_t streamId;
            memcpy(&streamId, handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            handle->aLayerBufferUsed += 4;

            uint64_t offset;
            memcpy(&offset,
                   handle->aLayerBuffer + handle->aLayerBufferUsed,
                   8);
            offset = ntohll(offset);
            handle->aLayerBufferUsed += 8;

            int rv = sdt_ResetStream_Internal(handle, streamId, offset, 0);
            if (rv) {
              return rv;
            }
          }
        case SDT_FRAME_TYPE_CONNECTION_CLOSE:
          // We are closing connection
          // TODO
          {
            fprintf(stderr, "SDT_FRAME_TYPE_CONNECTION_CLOSE received.\n");
            handle->state = SDT_CLOSING;
            uint32_t errorCode;
              memcpy(&errorCode, handle->aLayerBuffer + handle->aLayerBufferUsed,
                     4);
            errorCode =ntohl(errorCode);
            handle->aLayerBufferUsed += 4;

            uint16_t len;
            memcpy(&len, handle->aLayerBuffer + handle->aLayerBufferUsed, 2);
            len = ntohs(len);
            handle->aLayerBufferUsed += 2;

            assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= len);
            if ((handle->aLayerBufferUsed + len) == SDT_CLEARTEXTPAYLOADSIZE_MAX) {
              len--;
            }
            handle->aLayerBuffer[handle->aLayerBufferUsed + len] =0;
            fprintf(stderr, "SDT_FRAME_TYPE_CONNECTION_CLOSE - error %d, "
                            "error text: %s\n", errorCode,
                            handle->aLayerBuffer + handle->aLayerBufferUsed);
          }
          return SDTE_OK;
        case SDT_FRAME_TYPE_GOAWAY:
          {
            fprintf(stderr, "SDT_FRAME_TYPE_GOWAY received\n");

            uint32_t errorCode;
            memcpy(&errorCode, handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            errorCode =ntohl(errorCode);
            handle->aLayerBufferUsed += 4;

            uint32_t streamId;
            memcpy(&streamId, handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            streamId = ntohl(streamId);
            handle->aLayerBufferUsed += 4;

            // Get the length of error message.
            uint16_t len;
            memcpy(&len, handle->aLayerBuffer + handle->aLayerBufferUsed, 2);
            len = ntohs(len);
            handle->aLayerBufferUsed += 2;

            assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= len);

            if ((handle->aLayerBufferUsed + len) == SDT_CLEARTEXTPAYLOADSIZE_MAX) {
              len--;
            }
            handle->aLayerBuffer[handle->aLayerBufferUsed + len] =0;
            fprintf(stderr, "SDT_FRAME_TYPE_GOAWAY - error %d, "
                            "error text: %s\n", errorCode,
                            handle->aLayerBuffer + handle->aLayerBufferUsed);
//TODO!!!!
//            Received_GOAWAY(handle, streamId);
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

            uint64_t offset;
            memcpy(&offset, handle->aLayerBuffer + handle->aLayerBufferUsed,
                   8);
            offset = ntohll(offset);
            handle->aLayerBufferUsed += 8;

            Received_WINDOW_UPDATE(&handle->mSDTRecvDataStr, streamId, offset);
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

        case SDT_FRAME_TYPE_PING:
          {
            // Propagate PING to h2.
            fprintf(stderr, "SDT_FRAME_TYPE_PING received.\n");

#ifdef H2MAPPING
            H2_Make_PING(&handle->mSDTRecvDataStr);
#endif
          }
          break;

        case SDT_FRAME_TYPE_PRIORITY:
          {
//TODO not implemented
            fprintf(stderr, "SDT_FRAME_TYPE_PRIORITY received.\n");
            // Priority is not described readly.(there are 2 versions)
/*            assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >=
                   4 + 5);
            uint32_t streamId;
            memcpy(&streamId,
                   handle->aLayerBuffer + handle->aLayerBufferUsed,
                   4);
            handle->aLayerBufferUsed += 4;
            streamId = ntohl(streamId);

            assert((streamId != 1));

            if (streamId % 2) {
              streamId -= 2;
            }

            struct recvDataFrame_t *frame =
              (struct recvDataFrame_t*)malloc(sizeof(struct recvDataFrame_t) +
                                       HTTP2_HEADERLEN + 5);
            if (!frame) {
              return SDTE_OUT_OF_MEMORY;
            }
            frame->mNext = 0;
            frame->mOffset = 0;
            frame->mLength = 0;
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
            hAddSortedHttp2Frame(handle, frame);*/
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

#ifdef H2MAPPING
  return H2_Recv(&handle->mSDTRecvDataStr, buf, amount, flags);
#else
  return SDT_Recv(&handle->mSDTRecvDataStr, buf, amount, flags,
                  (handle->state == SDT_CONNECTING));
#endif
}

int32_t
sdt_GetData(PRFileDesc *fd)
{
//  fprintf(stderr, "%d sdt_GetData\n", PR_IntervalNow());

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

  sdt_DecodeFrames(handle);

  return 0;
}

#ifdef H2MAPPING

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
      break;
    case HTTP2_FRAME_TYPE_PRIORITY:
      minLen = 1 + 4 + 5;
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
      break;
    case HTTP2_FRAME_TYPE_GOAWAY:
      minLen = 1 + 4 + 4 + 2;
      break;
    case HTTP2_FRAME_TYPE_WINDOW_UPDATE:
      minLen = 1 + 4 + 8;
      break;
    case HTTP2_FRAME_TYPE_ALTSVC:
    case HTTP2_FRAME_TYPE_LAST:
      minLen = 0;
  }
  return minLen;
}

void
sdt_H22SDTStreamId(uint32_t h2StreamId, uint32_t *sdtStreamId)
{
  if (h2StreamId & 1) {
    sdtStreamId[0] = 2 * h2StreamId + 1;
    sdtStreamId[1] = 2 * h2StreamId + 3;
  } else {
    sdtStreamId[0] = 2 * h2StreamId -2;
    sdtStreamId[1] = 2 * h2StreamId;
  }
}

static void
H2_decodeH2Header(struct sdt_t *handle, const unsigned char *buf)
{
  handle->hType = ((uint8_t*)buf)[3];
  handle->hFlags = ((uint8_t*)buf)[3 + 1];
  memcpy(&handle->hDataLen, buf + 1, 2);
  handle->hDataLen = ntohs(handle->hDataLen);
  memcpy(&handle->hH2StreamId, buf + 3 + 1 + 1, 4);
  handle->hH2StreamId = ntohl(handle->hH2StreamId);
}

static uint8_t
H2_IsH2ControlFrame(uint8_t type)
{
  if ((type == HTTP2_FRAME_TYPE_DATA) ||
      (type == HTTP2_FRAME_TYPE_HEADERS) ||
      (type == HTTP2_FRAME_TYPE_CONTINUATION)) {
    return 0;
  }

  return 1;
}

static int
H2_MakeSDTControlFrameFromH2AndQueueIt(struct sdt_t *handle,
                                       const unsigned char *buf)
{
  int32_t read = 0;
  uint16_t size = hSDTFrameOrHeaderLen(handle->hType, handle->hFlags);

  uint16_t curr = 0;

  switch (handle->hType) {
    case HTTP2_FRAME_TYPE_PRIORITY:
    {
      fprintf(stderr, "HTTP2_FRAME_TYPE_PRIORITY\n");
      // Priority is not described readly.
      // TODO PRIORITY!!!
/*      chunkBuf[curr] = SDT_FRAME_TYPE_PRIORITY;
      curr += 1;
      uint32_t id = htonl(handle->hSDTStreamId);
      memcpy(chunkBuf + curr, &id, 4);
      curr += 4;
      memcpy(chunkBuf + curr, buf + read, 5);*/
      read += 5;
//      curr += 5;
      break;
    }

    case HTTP2_FRAME_TYPE_RST_STREAM:
    {
      fprintf(stderr, "HTTP2_FRAME_TYPE_RST_STREAM\n");
      // One h2 stream corresponds to 2 sdt streams.
      uint32_t sdtStreamId[2];
      sdt_H22SDTStreamId(handle->hH2StreamId, sdtStreamId);
      int32_t rv = sdt_ResetStream_Internal(handle, sdtStreamId[0], 0, 1);
      if (rv) {
        return rv;
      }
      rv = sdt_ResetStream_Internal(handle, sdtStreamId[1], 0, 1);
      if (rv) {
        return rv;
      }
      read += handle->hDataLen;
    }
    break;

    case HTTP2_FRAME_TYPE_SETTINGS:
    {
      fprintf(stderr, "HTTP2_FRAME_TYPE_SETTINGS\n");
      if (handle->hFlags & HTTP2_FRAME_FLAG_ACK) {
        // ignore ack.
      } else {
        // ignore but make a SETTING ACK frame
        int rc = H2_MakeSettingsSettingsAckFrame(&handle->mSDTRecvDataStr, 1);
        if (rc) {
          return rc;
        }
      }
      read += handle->hDataLen;
    }
    break;

    case HTTP2_FRAME_TYPE_PUSH_PROMISE:
      fprintf(stderr, "HTTP2_FRAME_TYPE_PUSH_PROMISE\n");
      assert(0);

    case HTTP2_FRAME_TYPE_PING:
      fprintf(stderr, "HTTP2_FRAME_TYPE_PING\n");
      // Ignore a PING ack.
      if (!(handle->hFlags & HTTP2_FRAME_FLAG_ACK)) {
        int32_t rv = sdt_send_PING(&handle->mSDTSendDataStr);
        if (rv) {
          return rv;
        }
      }
      read += 8;
      break;

    case HTTP2_FRAME_TYPE_GOAWAY:
      fprintf(stderr, "HTTP2_FRAME_TYPE_GOAWAY\n");

      uint32_t h2LastGoodStreamId;
      memcpy(&h2LastGoodStreamId, buf + read, 4);
      h2LastGoodStreamId = ntohl(h2LastGoodStreamId);
      uint32_t sdtStreamId[2];
      sdt_H22SDTStreamId(h2LastGoodStreamId, sdtStreamId);

      uint32_t error;
      memcpy(&error, buf + read + 4, 4);
      error = ntohl(error);

      uint16_t reasonLen = handle->hDataLen - 8;

      int32_t rv = sdt_send_GOAWAY(&handle->mSDTSendDataStr, error,
                                   sdtStreamId[1], reasonLen, buf + 8);
      if (rv) {
        return rv;
      }
      read += handle->hDataLen;
      break;

    case HTTP2_FRAME_TYPE_WINDOW_UPDATE:
    {
      fprintf(stderr, "HTTP2_FRAME_TYPE_WINDOW_UPDATE\n");
      // Ignoring!
      read += 4;
      break;
    }

    case HTTP2_FRAME_TYPE_ALTSVC:
      fprintf(stderr, "HTTP2_FRAME_TYPE_ALTSVC\n");
      read += handle->hDataLen;
      break;

    case HTTP2_FRAME_TYPE_LAST:
      fprintf(stderr, "HTTP2_FRAME_TYPE_LAST\n");
      read += handle->hDataLen;
      break;
    default:
      assert(0);
  }

  assert(curr == size);

  return read;
}

static int32_t
H2_DecodeH2Frames(struct sdt_t *handle, const unsigned char *buf, uint32_t amount)
{
  LogBuffer("DecodeH2Frames", buf, amount);

  uint8_t done = 0;
  int32_t read = 0;

  // TODO: SDT will send the setting as part of tls handshake.
  if (!handle->hMagicHello) {
    // 24 + 4
    if (amount < 28) {
      done = 1;
    } else {
      if (memcmp(buf, magicHello, 24)) {
        assert(0);
      }
      handle->hMagicHello = 1;
      read = 24;
    }
  }

  while (!done && (amount - read)) {
    switch (handle->hState) {
      case SDT_H2S_NEWFRAME:
      {
        // If we do not have the whole http2 header, we cannot do much.
        if ((amount - read) < HTTP2_HEADERLEN) {
          done = 1;
          continue;
        }

        // Decode h2 common header.
        H2_decodeH2Header(handle, buf + read);

        // We will decode control packets only if the complete h2 frame is in
        // the buffer. For other frames we want to have only the complete
        // header and the padding info.

        if (H2_IsH2ControlFrame(handle->hType)) {
          if ((amount - read) < (HTTP2_HEADERLEN + handle->hDataLen)) {
            done = 1;
            continue;
          }
        } else {
          // Decode Padding for DATA, HEADER and CONTINUATION frame.
          handle->hPadding = 0;
          if (handle->hFlags & HTTP2_FRAME_FLAG_PADDED) {
            if ((amount - read) < (HTTP2_HEADERLEN + 1)) {
              done = 1;
              continue;
            }
            handle->hPadding = ((uint8_t*)buf)[read + HTTP2_HEADERLEN];
            // fix data length.
            handle->hDataLen -= 1;
            handle->hDataLen -= handle->hPadding;
          }
        }

        // After h2 common header and padding are decoded we can move on
        read += HTTP2_HEADERLEN + ((handle->hPadding) ? 1 : 0);
        if (H2_IsH2ControlFrame(handle->hType)) {
          int rc = H2_MakeSDTControlFrameFromH2AndQueueIt(handle, buf + read);
          if (rc < 0) {
            return rc;
          }
          read += rc;
        } else {
          uint32_t sdtStreamId[2];
          sdt_H22SDTStreamId(handle->hH2StreamId, sdtStreamId);
          if ((sdtStreamId[0] & 1) != handle->isServer) {
            // This is a localy stream!!!
            if (!handle->mNextStreamIdLocal) {
              // TODO make GOWAY
              return SDTE_NO_MORE_STREAM_IDS;
            }
            assert(handle->mNextStreamIdLocal <= sdtStreamId[0]);
            if (handle->mNextStreamIdLocal == sdtStreamId[0]) {
              uint32_t streamId;
              int32_t rv = sdt_CreateStream(handle, &streamId);
              if (rv) {
                return rv;
              }
              assert(sdtStreamId[0] == streamId);
              rv = sdt_CreateStream(handle, &streamId);
              if (rv) {
                return rv;
              }
              assert(sdtStreamId[1] == streamId);
            }
          } else {
            // This is remote stream. The stream must be already opened.
            assert(!handle->mNextStreamIdRemote ||
                   (handle->mNextStreamIdRemote > sdtStreamId[1]));
          }
          int32_t streamId;
          if ((sdtStreamId[0] % 2) != handle->isServer) {
            streamId = sdtStreamId[0];
          } else {
            streamId = sdtStreamId[1];
          }
          if (handle->hType == HTTP2_FRAME_TYPE_DATA) {
            handle->hCurrentDataChunk =
              sdt_send_CreateDataChunkStreamId(&handle->mSDTSendDataStr,
                                               streamId,
                                               handle->hDataLen);
            if (handle->hFlags & HTTP2_FRAME_FLAG_END_STREAM) {
              sdt_send_CloseStream(&handle->mSDTSendDataStr,
                                   handle->hSDTStreamId);
            }
          } else {
            handle->hCurrentDataChunk =
              sdt_send_CreateDataChunkStreamId(&handle->mSDTSendDataStr, 3,
                                               handle->hDataLen +  HTTP2_HEADERLEN);
          }

          if (!handle->hCurrentDataChunk) {
            return SDTE_OUT_OF_MEMORY;
          }

          if (handle->hType != HTTP2_FRAME_TYPE_DATA) {
            // For Headers we are sending complete h2 headers as well!
            if (handle->hFlags & HTTP2_FRAME_FLAG_PADDED) {
              int32_t rv = sdt_send_WriteDataToDataChunk(&handle->mSDTSendDataStr,
                                                         handle->hCurrentDataChunk,
                                                         buf + read - HTTP2_HEADERLEN,
                                                         1);
              if (rv < 0) {
                return rv;
              }
              uint16_t len = htons(handle->hDataLen);
              rv = sdt_send_WriteDataToDataChunk(&handle->mSDTSendDataStr,
                                                 handle->hCurrentDataChunk,
                                                 &len, 2);
              if (rv < 0) {
                return rv;
              }
              rv = sdt_send_WriteDataToDataChunk(&handle->mSDTSendDataStr,
                                                 handle->hCurrentDataChunk,
                                                 buf + read - HTTP2_HEADERLEN + 3,
                                                 1);
              if (rv < 0) {
                return rv;
              }
              int8_t flag = buf[read - HTTP2_HEADERLEN + 4] & ~HTTP2_FRAME_FLAG_PADDED;
              rv = sdt_send_WriteDataToDataChunk(&handle->mSDTSendDataStr,
                                                 handle->hCurrentDataChunk,
                                                 &flag, 1);
              if (rv < 0) {
                return rv;
              }
              streamId = htonl(streamId);
              rv = sdt_send_WriteDataToDataChunk(&handle->mSDTSendDataStr,
                                                 &streamId,
                                                 buf + read - HTTP2_HEADERLEN + 5,
                                                 4);
              if (rv < 0) {
                return rv;
              }
            } else {
              int32_t rv = sdt_send_WriteDataToDataChunk(&handle->mSDTSendDataStr,
                                                         handle->hCurrentDataChunk,
                                                         buf + read - HTTP2_HEADERLEN,
                                                         HTTP2_HEADERLEN);
              if (rv < 0) {
                return rv;
              }
            }
          }

          fprintf(stderr, "HTTP2_FRAME_TYPE_DATA or HEADERS or "
                          "CONTINUATION\n");
          handle->hState = SDT_H2S_FILLFRAME;
        }
        break;
      }
      case SDT_H2S_FILLFRAME:
      {
        fprintf(stderr, "SDT_H2S_FILLFRAME\n");
        assert(!H2_IsH2ControlFrame(handle->hType));

        uint16_t toRead = ((amount - read) > handle->hDataLen) ?
          handle->hDataLen : (amount - read);

        int32_t rv = sdt_send_WriteDataToDataChunk(&handle->mSDTSendDataStr,
                                                   handle->hCurrentDataChunk, buf + read,
                                                   toRead);
        if (rv < 0) {
          return rv;
        }

        assert(rv == toRead);

        read += toRead;
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
        assert(!H2_IsH2ControlFrame(handle->hType));

        uint32_t len = ((amount - read) > handle->hPadding) ?
                       handle->hPadding : (amount - read);
        read += len;
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
  return read;
}
#endif

static int32_t
MaybeQueueData(struct sdt_t *handle, const unsigned char *buf, uint32_t amount)
{
  if (!amount) {
    return SDTE_OK;
  }

#ifdef H2MAPPING
  return H2_DecodeH2Frames(handle, buf, amount);
#else

  return sdt_send_MaybeBufferData(&handle->mSDTSendDataStr, buf, amount);

#endif
}

static int32_t
PreparePacketDataAndAck(struct sdt_t *handle, struct aPacket_t *pkt)
{
  if (DoWeNeedToSendAck(handle)) {
    MakeAckPkt(handle, pkt);
  }

  return PreparePacket(&handle->mSDTSendDataStr, pkt, handle->aNextPacketId);
}

static int32_t
MaybeSendPacket(PRFileDesc *fd, struct sdt_t *handle)
{
  fprintf(stderr, "MaybeSendPacket numOfRTORetrans=%d\n",
          handle->numOfRTORetrans);
  // 1) Check if a timer expired
  CheckRetransmissionTimers(handle);
  if (handle->numOfRTORetrans > aMaxNumOfRTORetrans) {
    PR_SetError(PR_IO_TIMEOUT_ERROR, 0);
    return -1;
  }

  fprintf(stderr, "MaybeSendPacket cc->CanSend=%d, "
          "sdt_send_HasDataForTransmission=%d\n",
          cc->CanSend(&handle->ccData),
          sdt_send_HasDataForTransmission(&handle->mSDTSendDataStr));
  // 2) check cc limit.
  if (!cc->CanSend(&handle->ccData) ||
      (!sdt_send_HasDataForTransmission(&handle->mSDTSendDataStr) &&
       !DoWeNeedToSendAck(handle))) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  // 3) Send a packet.
  // Because of the congestion control we need to send as much as we can.
  // (SocketTransport we call read, then write then read... on the socket.
  //  If ack arrives and increases cwnd, write must be called more than once
  //  to send as much as we can. If we do not do that, if we call it just
  //  once bytes_in_flights will be less than cwnd and on the next ack cc is
  //  app limited.)
  struct aPacket_t *pkt =
    (struct aPacket_t *) malloc (sizeof(struct aPacket_t) +
                                 handle->cleartextpayloadsize);
  if (!pkt) {
    return SDTE_OUT_OF_MEMORY;
  }
  pkt->mSize = handle->cleartextpayloadsize;

  int32_t rv = 0;
  do {
    pkt->mWritten = 0;

    rv = PreparePacketDataAndAck(handle, pkt);
    if (rv) {
      free(pkt);
    }

    if (pkt->mWritten) {
      unsigned char *pktBuf = (unsigned char *)(pkt + 1);

      rv = fd->lower->methods->write(fd->lower,
                                     pktBuf,
                                     pkt->mWritten);

      LogBuffer("MaybeSendPacket - pkt buffer: ", pktBuf, pkt->mWritten);
      fprintf(stderr, "MaybeSendPacket rv=%d\n", rv);

      if ((rv > 0) && PacketSent(&handle->mSDTSendDataStr, 1)) {
        // We have sent a packet!

        // Start rto timer if needed. The RTO timer is started only for data
        // packets.
        MaybeStartRTOTimer(handle);
      } else {
        // Packet has not been sent, so remove it.
        PacketSent(&handle->mSDTSendDataStr, 0);
      }
    }
  } while (pkt->mWritten && (rv > 0) &&
           sdt_send_HasDataForTransmission(&handle->mSDTSendDataStr) &&
           cc->CanSend(&handle->ccData));

  free(pkt);
  return rv;
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

      fprintf(stderr, "aLayerWrite state=SDT_TRANSFERRING\n");

      // Queue data for transmission!
      int32_t dataRead = MaybeQueueData(handle, buf, amount);
      fprintf(stderr, "aLayerWrite: data read %d\n", dataRead);

      if (dataRead < 0) {
        return dataRead;
      }

      int32_t rv = MaybeSendPacket(fd, handle);
      if (rv <= 0 && (PR_GetError() != PR_WOULD_BLOCK_ERROR)) {
        return rv;
      }

      if (dataRead) {
        return dataRead;
      } else {
        PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
        return -1;
      }
    }
    break;
  case SDT_CLOSING:
    // TODO CLOSING part!!!
    assert (0);
  }

  return -1;
}

static int
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

static void
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
  if (cc->CanSend(&handle->ccData) || !amount) {
    rv = fd->lower->methods->write(fd->lower, buf, amount);
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
        !(cc->CanSend(&handle->ccData) ||
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
          sdt_send_HasDataForTransmission(&handle->mSDTSendDataStr) ||
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

#ifdef H2MAPPING
  return (handle->mSDTRecvDataStr.mH2OrderedFramesFirst != 0);
#else
  return (handle->mSDTRecvDataStr.mReadyStreamsFirst != 0);
#endif
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

  return sdt_send_CanSendData(&handle->mSDTSendDataStr);
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

int32_t
sdt_OpenStream(PRFileDesc * fd, uint32_t *streamId)
{
  assert(PR_GetLayersIdentity(fd) == aIdentity);
  assert(streamId);
  *streamId = 0;

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }

  if (!handle->mNextStreamIdLocal) {
    return SDTE_NO_MORE_STREAM_IDS;
  }

  return sdt_CreateStream(handle, streamId);
}
int32_t
sdt_CloseStream(PRFileDesc *fd, uint32_t streamId)
{
  assert(PR_GetLayersIdentity(fd) == aIdentity);
  assert(streamId);

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }

  return sdt_LocalCloseStream(handle, streamId);
}

int32_t
sdt_ResetStream(PRFileDesc *fd, uint32_t streamId)
{
  assert(PR_GetLayersIdentity(fd) == aIdentity);
  assert(streamId);

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }

  int32_t rv = sdt_ResetStream_Internal(handle, streamId, 0, 1);
  assert(!rv);

  return sdt_send_RST_STREAM(&handle->mSDTSendDataStr, streamId, 1);
}

int32_t
sdt_GetStreamsReadyToRead(PRFileDesc * fd, uint32_t **streamIds, uint32_t *num)
{
#ifndef H2MAPPING
  assert(PR_GetLayersIdentity(fd) == aIdentity);
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }

  if (!handle->mSDTRecvDataStr.mReadyStreamsFirst) {
    num = 0;
    return SDTE_OK;
  }

  *streamIds = (uint32_t *) malloc (4 * handle->mSDTRecvDataStr.mReadyStreamsNum);

  struct recvStream_t *stream = handle->mSDTRecvDataStr.mReadyStreamsFirst;
  uint32_t n = 0;
  while (stream) {
    *streamIds[n++] = stream->mStreamId;
    stream = stream->mNextReadyStream;
  }
  *num =n;
#endif
  return SDTE_OK;
}

int32_t
sdt_SetNextStreamToRead(PRFileDesc * fd, uint32_t streamId)
{
#ifndef H2MAPPING
  assert(PR_GetLayersIdentity(fd) == aIdentity);
  assert(streamId); // cannot be 0.

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }
  assert(!handle->mSDTRecvDataStr.mNextToReadSet);

  if (!streamId) {
    handle->mSDTRecvDataStr.mNextToReadSet = 0;
    handle->mSDTRecvDataStr.mNextToReadId = 0;
  } else {
    struct recvStream_t *streamInfo =
      sdt_recv_FindStream(&handle->mSDTRecvDataStr, streamId);
    if (streamInfo->mStreamReset) {
      return SDT_STREAM_RST;
    } else if (streamInfo->mState == STREAM_CLOSED) {
      return SDT_STREAM_FIN;
    }

    handle->mSDTRecvDataStr.mNextToReadSet = 1;
    handle->mSDTRecvDataStr.mNextToReadId = streamId;
  }
#endif
  return SDTE_OK;
}

int32_t
sdt_SetNextStreamToWrite(PRFileDesc * fd, uint32_t streamId)
{
  fprintf(stderr, "sdt_SetNextStreamToWrite %lu\n", streamId);
  assert(PR_GetLayersIdentity(fd) == aIdentity);

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }
  assert(!handle->mSDTSendDataStr.mNextToWriteSet);

  if (!streamId) {
    handle->mSDTSendDataStr.mNextToWriteSet = 0;
    handle->mSDTSendDataStr.mNextToWriteId = 0;
  } else {
    struct aOutgoingStreamInfo_t *streamInfo =
      sdt_send_FindStream(&handle->mSDTSendDataStr, streamId);
    fprintf(stderr, "sdt_SetNextStreamToWrite %p closed=%d reset=%d\n",
            streamInfo, streamInfo->mState == STREAM_CLOSED,
            streamInfo->mStreamReset);
    if (streamInfo->mStreamReset) {
      return SDT_STREAM_RST;
    } else if (streamInfo->mState == STREAM_CLOSED) {
      return SDT_STREAM_FIN;
    }
    handle->mSDTSendDataStr.mNextToWriteSet = 1;
    handle->mSDTSendDataStr.mNextToWriteId = streamId;
  }

  return SDTE_OK;
}

uint8_t
sdt_StreamCanWriteData(PRFileDesc * fd, uint32_t streamId)
{
  assert(PR_GetLayersIdentity(fd) == aIdentity);
  assert(streamId); // cannot be 0

  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }

  struct aOutgoingStreamInfo_t *stream = sdt_send_FindStream(&handle->mSDTSendDataStr,
                                                             streamId);
  if (!stream) {
    return 0;
  }

  return sdt_send_CanSendDataStream(&handle->mSDTSendDataStr, stream);
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

  cc = &sdt_cc;
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

  return sdt_addSDTLayers(fd, 0);
}

PRFileDesc *
sdt_addSDTLayers(PRFileDesc *fd, uint8_t isServer)
{
  PRFileDesc *sLayer = NULL;

  sLayer = PR_CreateIOLayerStub(sIdentity, &sMethods);

  if (!(fd && sLayer)) {
    goto fail; // ha!
  }

  sLayer->dtor = strongDtor;

  struct sdt_t *handle = sdt_newHandle(isServer);
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
