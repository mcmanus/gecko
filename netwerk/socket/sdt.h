/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef SDT_SOCKET
#define SDT_SOCKET

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "prio.h"

#define SDT_MTU 1400
#define SDT_PAYLOADSIZE_IPV4 1370
#define SDT_PAYLOADSIZE_IPV6 1350
#define SDT_PAYLOADSIZE_DIFF (SDT_PAYLOADSIZE_IPV4 - SDT_PAYLOADSIZE_IPV6)
#define SDT_PAYLOADSIZE_MAX SDT_PAYLOADSIZE_IPV4
#define DTLS_PART 37
#define SDT_CLEARTEXTPAYLOADSIZE_IPV4 (SDT_PAYLOADSIZE_IPV4 - DTLS_PART)
#define SDT_CLEARTEXTPAYLOADSIZE_IPV6 (SDT_PAYLOADSIZE_IPV6 - DTLS_PART)
#define SDT_CLEARTEXTPAYLOADSIZE_MAX SDT_CLEARTEXTPAYLOADSIZE_IPV4
#define SDT_REPLAY_WINDOW 8192

PRFileDesc *sdt_openSocket(PRIntn af);
PRFileDesc *sdt_addSDTLayers(PRFileDesc *fd, uint8_t isServer);
PRFileDesc *sdt_addALayer(PRFileDesc *fd);
void sdt_ensureInit();

uint16_t sdt_GetNextTimer(PRFileDesc *fd);

//Needed for FF socketThread loop.
int32_t sdt_GetData(PRFileDesc *fd);
uint8_t sdt_HasData(PRFileDesc *fd);
uint8_t sdt_SocketWritable(PRFileDesc *fd);

int32_t sdt_OpenStream(PRFileDesc *fd, uint32_t *streamId);
int32_t sdt_CloseStream(PRFileDesc *fd, uint32_t streamId);
int32_t sdt_ResetStream(PRFileDesc *fd, uint32_t streamId);
int32_t sdt_GetStreamsReadyToRead(PRFileDesc *aFd, uint32_t **streamIds,
                                  uint32_t *num);

// This can return SDT_STREAM_RST if stream was been reset by the remote peer or
// SDT_STREAM_FIN if it is closed.
int32_t  sdt_SetNextStreamToRead(PRFileDesc *aFd, uint32_t streamId);

int32_t sdt_SetNextStreamToWrite(PRFileDesc *aFd, uint32_t streamId);
uint8_t sdt_StreamCanWriteData(PRFileDesc *aFd, uint32_t streamId);

/* error codes */
#define SDTE_OK             0
#define SDTE_FATAL_ERROR   -1
#define SDTE_OUT_OF_MEMORY -2
#define SDTE_NOT_AVAILABLE -3
#define SDTE_NO_MORE_STREAM_IDS -4
#define SDTE_WOULD_BLOCK -5
#define SDTE_PROTOCOL_ERROR -6
#define SDTE_STREAM_DELETED -7

#define SDT_STREAM_RST -101
#define SDT_STREAM_FIN -102

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif //SDT_SOCKET
