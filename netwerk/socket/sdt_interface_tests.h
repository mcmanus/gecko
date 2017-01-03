
#ifndef SDT_SOCKET_TESTS
#define SDT_SOCKET_TESTS

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdint.h>

enum ChunkType {
  DATA_CHUNK,
  HEADER_CHUNK,
  CONTROL_CHUNK
};


struct aDataChunk_t;

void LogRanges(struct aDataChunk_t *chunk);
struct aDataChunk_t * CreateChunk(enum ChunkType type, uint32_t size,
                                  uint32_t flags, uint32_t streamId);
int32_t ChunkRefCnt(struct aDataChunk_t *chunk);
void ChunkAddRef(struct aDataChunk_t *chunk);
void AddNewRange(struct aDataChunk_t *chunk, uint32_t start, uint32_t end);
uint8_t HasNotSentRange(struct aDataChunk_t *chunk, uint32_t start, uint32_t end);
uint32_t NumNotSentRanges(struct aDataChunk_t *chunk);
uint8_t HasUnackedRange(struct aDataChunk_t *chunk, uint32_t start, uint32_t end);
uint32_t NumUnackedRanges(struct aDataChunk_t *chunk);
int32_t SomeDataSentFromChunk(struct aDataChunk_t *chunk, uint16_t len);
int32_t AckSomeDataSentFromChunk(struct aDataChunk_t *chunk, uint32_t start,
                                 uint32_t end);
int32_t SomeDataLostFromChunk(struct aDataChunk_t *chunk, uint32_t start,
                              uint32_t end);
void FreeDataChunk(struct aDataChunk_t *chunk);

struct SDT_SendDataStruct_t * CreateNewSDTSendDataStr();
void ClearSDTSendDataStr(struct SDT_SendDataStruct_t *sendDataStr);
struct aPacket_t * CreatePacket(uint32_t size);
struct aDataChunk_t * CreateDataChunkForTest(struct SDT_SendDataStruct_t *sendDataStr,
                                             uint32_t streamId, uint32_t size);
int32_t AddChunkRange(struct SDT_SendDataStruct_t *sendDataStr,
                      struct aDataChunk_t *chunk, uint32_t start, uint32_t end);
int32_t PreparePacket(struct SDT_SendDataStruct_t *sendDataStr,
                      struct aPacket_t *pkt, uint64_t nextPacketId);
uint8_t PacketSent(struct SDT_SendDataStruct_t *sendDataStr, uint8_t sent);
int32_t MarkPacketLostWithId(struct SDT_SendDataStruct_t *sendDataStr,
                             uint32_t pktSeqNum);
struct aPacketInfo_t * PacketAcked(struct SDT_SendDataStruct_t *sendDataStr, uint64_t seqNum);
uint8_t HasDataForTransmission(struct SDT_SendDataStruct_t *sendDataStr);
uint8_t HasUnackedPackets(struct SDT_SendDataStruct_t *sendDataStr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif //SDT_SOCKET_TESTS
