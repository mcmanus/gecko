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
PRFileDesc *sdt_addSDTLayers(PRFileDesc *aFd);
PRFileDesc *sdt_addALayer(PRFileDesc *aFd);
void sdt_ensureInit();

uint16_t sdt_GetNextTimer(PRFileDesc *aFd);

//Needed for FF socketThread loop.
int32_t sdt_GetData(PRFileDesc *aFd);
uint8_t sdt_HasData(PRFileDesc *aFd);
uint8_t sdt_SocketWritable(PRFileDesc *aFd);

struct sdt_t;
void *sdt_GetCCPrivate(struct sdt_t *sdt);


/* error codes */
#define SDTE_OK             0
#define SDTE_OUT_OF_MEMORY -1

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif //SDT_SOCKET
