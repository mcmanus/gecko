#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "sdt_interface_tests.h"
#include <assert.h>
#include <stdlib.h>

struct aDataChunk_t;

int main()
{

  // Marking a packet as lost twice will ASSERT!!!!
  // Marking a packet as acked twice will ASSERT!!!
  // Marking a already acked packet as lost will ASSERT!!!!
  // It is possible to marked a already lost packet as acked (spurious retransmissions)!!!!

  struct SDT_SendDataStruct_t *str = CreateNewSDTSendDataStr();

  // This will add chunk to streamInfo queue and add ref as well.
  struct aDataChunk_t *chunk1 = CreateDataChunkForTest(str, 5, 30);
  assert(ChunkRefCnt(chunk1) == 1);
  // Add ref from here (so that chunk will not be freed);
  ChunkAddRef(chunk1);
  assert(ChunkRefCnt(chunk1) == 2);

  // This adds chunk to transmission queue and adds ref as well.
  AddChunkRange(str, chunk1, 0, 30);
  assert(ChunkRefCnt(chunk1) == 3);

  struct aDataChunk_t *chunk2 = CreateDataChunkForTest(str, 5, 30);
  ChunkAddRef(chunk2);
  AddChunkRange(str, chunk2, 0, 30);
  assert(ChunkRefCnt(chunk2) == 3);

  struct aDataChunk_t *chunk3 = CreateDataChunkForTest(str, 7, 30);
  ChunkAddRef(chunk3);
  AddChunkRange(str, chunk3, 0, 30);
  assert(ChunkRefCnt(chunk3) == 3);

  struct aPacket_t *pkt;
  uint32_t nextPacketId = 0;
  while (nextPacketId< 4) {
    pkt = CreatePacket(22);
    assert(HasDataForTransmission(str));
    PreparePacket(str, pkt, nextPacketId++);
    PacketSent(str, 1);
    free(pkt);
  }

  // first 4 are sent only from chunk 1.
  assert(NumNotSentRanges(chunk1) == 1);
  assert(NumUnackedRanges(chunk1) == 1);
  assert(HasNotSentRange(chunk1, 28, 30));
  assert(HasUnackedRange(chunk1, 0, 28));
  // 4 packet infos hold ref to this chunk!
  assert(ChunkRefCnt(chunk1) == 7);

  assert(NumNotSentRanges(chunk2) == 1);
  assert(NumUnackedRanges(chunk2) == 0);
  assert(HasNotSentRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 3);

  assert(NumNotSentRanges(chunk3) == 1);
  assert(NumUnackedRanges(chunk3) == 0);
  assert(HasNotSentRange(chunk3, 0, 30));
  assert(ChunkRefCnt(chunk3) == 3);

  pkt = CreatePacket(22);
  PreparePacket(str, pkt, nextPacketId++);
  PacketSent(str, 1);
  free(pkt);

  // 5th packet contains data from chunk1(2bytes) and chunk2 (5bytes), they are
  // concatenated.
  assert(NumNotSentRanges(chunk1) == 0);
  assert(NumUnackedRanges(chunk1) == 1);
  assert(HasUnackedRange(chunk1, 0, 30));
  // The whole chunk1 was been transmitted so it is removed from the
  // transmission queue and ref as well!
  //(5 packet infos, stream info queue, and from here)
  assert(ChunkRefCnt(chunk1) == 7);

  assert(NumNotSentRanges(chunk2) == 1);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasNotSentRange(chunk2, 5, 30));
  assert(HasUnackedRange(chunk2, 0, 5));
  assert(ChunkRefCnt(chunk2) == 4);

  assert(NumNotSentRanges(chunk3) == 1);
  assert(NumUnackedRanges(chunk3) == 0);
  assert(HasNotSentRange(chunk3, 0, 30));
  assert(ChunkRefCnt(chunk3) == 3);

  while (nextPacketId < 8) {
    pkt = CreatePacket(22);
    assert(HasDataForTransmission(str));
    PreparePacket(str, pkt, nextPacketId++);
    PacketSent(str, 1);
    free(pkt);
  }

  // after 8th packet in chunk2 there are 4 bytes left not sent.
  assert(NumNotSentRanges(chunk1) == 0);
  assert(NumUnackedRanges(chunk1) == 1);
  assert(HasUnackedRange(chunk1, 0, 30));
  assert(ChunkRefCnt(chunk1) == 7);

  assert(NumNotSentRanges(chunk2) == 1);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasNotSentRange(chunk2, 26, 30));
  assert(HasUnackedRange(chunk2, 0, 26));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 1);
  assert(NumUnackedRanges(chunk3) == 0);
  assert(HasNotSentRange(chunk3, 0, 30));
  assert(ChunkRefCnt(chunk3) == 3);

  pkt = CreatePacket(22);
  PreparePacket(str, pkt, nextPacketId++);
  PacketSent(str, 1);
  free(pkt);

  // after 10th packet only the last data from chunk2 are sent. chunk3 belongs
  // to a different stream and they cannot be concatenate.
  assert(NumNotSentRanges(chunk1) == 0);
  assert(NumUnackedRanges(chunk1) == 1);
  assert(HasUnackedRange(chunk1, 0, 30));
  assert(ChunkRefCnt(chunk1) == 7);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 1);
  assert(NumUnackedRanges(chunk3) == 0);
  assert(HasNotSentRange(chunk3, 0, 30));
  assert(ChunkRefCnt(chunk3) == 3);

  while (nextPacketId < 14) {
    pkt = CreatePacket(22);
    assert(HasDataForTransmission(str));
    PreparePacket(str, pkt, nextPacketId++);
    PacketSent(str, 1);
    free(pkt);
  }

  // all data is sent.
  assert(NumNotSentRanges(chunk1) == 0);
  assert(NumUnackedRanges(chunk1) == 1);
  assert(HasUnackedRange(chunk1, 0, 30));
  assert(ChunkRefCnt(chunk1) == 7);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 0);
  assert(NumUnackedRanges(chunk3) == 1);
  assert(HasUnackedRange(chunk3, 0, 30));
  assert(ChunkRefCnt(chunk3) == 7);

  // Marked some packets lost
  MarkPacketLostWithId(str, 2);
  assert(HasDataForTransmission(str));
  assert(NumNotSentRanges(chunk1) == 1);
  assert(NumUnackedRanges(chunk1) == 2);
  assert(HasNotSentRange(chunk1, 14, 21));
  assert(HasUnackedRange(chunk1, 0, 14));
  assert(HasUnackedRange(chunk1, 21, 30));
  // Lost packet keeps ref, and the transmission queue adds one.
  assert(ChunkRefCnt(chunk1) == 8);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 0);
  assert(NumUnackedRanges(chunk3) == 1);
  assert(HasUnackedRange(chunk3, 0, 30));
  assert(ChunkRefCnt(chunk3) == 7);

  MarkPacketLostWithId(str, 3);
  assert(HasDataForTransmission(str));
  assert(NumNotSentRanges(chunk1) == 1);
  assert(NumUnackedRanges(chunk1) == 2);
  assert(HasNotSentRange(chunk1, 14, 28));
  assert(HasUnackedRange(chunk1, 0, 14));
  assert(HasUnackedRange(chunk1, 28, 30));
  assert(ChunkRefCnt(chunk1) == 8);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 0);
  assert(NumUnackedRanges(chunk3) == 1);
  assert(HasUnackedRange(chunk3, 0, 30));
  assert(ChunkRefCnt(chunk3) == 7);

  MarkPacketLostWithId(str, 12);
  assert(HasDataForTransmission(str));
  assert(NumNotSentRanges(chunk1) == 1);
  assert(NumUnackedRanges(chunk1) == 2);
  assert(HasNotSentRange(chunk1, 14, 28));
  assert(HasUnackedRange(chunk1, 0, 14));
  assert(HasUnackedRange(chunk1, 28, 30));
  assert(ChunkRefCnt(chunk1) == 8);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 1);
  assert(NumUnackedRanges(chunk3) == 2);
  assert(HasNotSentRange(chunk3, 21, 28));
  assert(HasUnackedRange(chunk3, 0, 21));
  assert(HasUnackedRange(chunk3, 28, 30));
  assert(ChunkRefCnt(chunk3) == 8);

  pkt = CreatePacket(50);
  PreparePacket(str, pkt, nextPacketId++);
  PacketSent(str, 1);
  free(pkt);

  assert(HasDataForTransmission(str));
  assert(NumNotSentRanges(chunk1) == 0);
  assert(NumUnackedRanges(chunk1) == 1);
  assert(HasUnackedRange(chunk1, 0, 30));
  // New packet sent, and removed from the transmission queue.
  assert(ChunkRefCnt(chunk1) == 8);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 1);
  assert(NumUnackedRanges(chunk3) == 2);
  assert(HasNotSentRange(chunk3, 27, 28));
  assert(HasUnackedRange(chunk3, 0, 27));
  assert(HasUnackedRange(chunk3, 28, 30));
  // New packet sent but still in transmission queue.
  assert(ChunkRefCnt(chunk3) == 9);

  pkt = CreatePacket(50);
  PreparePacket(str, pkt, nextPacketId++);
  PacketSent(str, 1);
  free(pkt);

  assert(!HasDataForTransmission(str));
  assert(NumNotSentRanges(chunk1) == 0);
  assert(NumUnackedRanges(chunk1) == 1);
  assert(HasUnackedRange(chunk1, 0, 30));
  assert(ChunkRefCnt(chunk1) == 8);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 0);
  assert(NumUnackedRanges(chunk3) == 1);
  assert(HasUnackedRange(chunk3, 0, 30));
  assert(ChunkRefCnt(chunk3) == 9);

  PacketAcked(str, 0);
  PacketAcked(str, 1);
  PacketAcked(str, 3);
  assert(!HasDataForTransmission(str));
  assert(NumNotSentRanges(chunk1) == 0);
  assert(NumUnackedRanges(chunk1) == 2);
  assert(HasUnackedRange(chunk1, 14, 21));
  assert(HasUnackedRange(chunk1, 28, 30));
  assert(ChunkRefCnt(chunk1) == 5);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 0);
  assert(NumUnackedRanges(chunk3) == 1);
  assert(HasUnackedRange(chunk3, 0, 30));
  assert(ChunkRefCnt(chunk3) == 9);

  // Packet 14 retransmitted some data that was sent in packet 2 and 3 (they
  // were marked as lost).
  // Packet 3 was later marked as acked (spurious retransmissions!).
  // After packet 14 is marked as lost we should not marked already acked data
  // (from packet 3) as lost!
  MarkPacketLostWithId(str, 14);
  assert(HasDataForTransmission(str));
  assert(NumNotSentRanges(chunk1) == 1);
  assert(NumUnackedRanges(chunk1) == 1);
  assert(HasNotSentRange(chunk1, 14, 21));
  assert(HasUnackedRange(chunk1, 28, 30));
  assert(ChunkRefCnt(chunk1) == 6);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 1);
  assert(NumUnackedRanges(chunk3) == 2);
  assert(HasNotSentRange(chunk3, 21, 27));
  assert(HasUnackedRange(chunk3, 0, 21));
  assert(HasUnackedRange(chunk3, 27, 30));
  assert(ChunkRefCnt(chunk3) == 10);

  // Wrongly marked as lost, but data are still not retransmitted!
  PacketAcked(str, 14);
  assert(!HasDataForTransmission(str));
  assert(NumNotSentRanges(chunk1) == 0);
  assert(NumUnackedRanges(chunk1) == 1);
  assert(HasUnackedRange(chunk1, 28, 30));
  assert(ChunkRefCnt(chunk1) == 4);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 0, 30));
  assert(ChunkRefCnt(chunk2) == 7);

  assert(NumNotSentRanges(chunk3) == 0);
  assert(NumUnackedRanges(chunk3) == 2);
  assert(HasUnackedRange(chunk3, 0, 21));
  assert(HasUnackedRange(chunk3, 27, 30));
  assert(ChunkRefCnt(chunk3) == 8);

  PacketAcked(str, 2);
  PacketAcked(str, 4);

  assert(!HasDataForTransmission(str));
  assert(NumNotSentRanges(chunk1) == 0);
  assert(NumUnackedRanges(chunk1) == 0);
  assert(ChunkRefCnt(chunk1) == 1);

  assert(NumNotSentRanges(chunk2) == 0);
  assert(NumUnackedRanges(chunk2) == 1);
  assert(HasUnackedRange(chunk2, 5, 30));
  assert(ChunkRefCnt(chunk2) == 6);

  assert(NumNotSentRanges(chunk3) == 0);
  assert(NumUnackedRanges(chunk3) == 2);
  assert(HasUnackedRange(chunk3, 0, 21));
  assert(HasUnackedRange(chunk3, 27, 30));
  assert(ChunkRefCnt(chunk3) == 8);

  ClearSDTSendDataStr(str);
  free(str);

  assert(!HasDataForTransmission(str));
  assert(ChunkRefCnt(chunk1) == 1);
  assert(ChunkRefCnt(chunk2) == 1);
  assert(ChunkRefCnt(chunk3) == 1);

  FreeDataChunk(chunk1);
  FreeDataChunk(chunk2);
  FreeDataChunk(chunk3);
}


#ifdef __cplusplus
}
#endif /* __cplusplus */
