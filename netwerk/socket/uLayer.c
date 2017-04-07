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
#include "ssl.h"
#include "unistd.h"

// DEV_ABORT's might actually happen in the wild, but in the lab are more
// likely to be a bug.. so we will abort on them for now, but they need a
// runtime error path too.
#if 1
#define DEV_ABORT(x) do { abort(); } while (0)
#else
#define DEV_ABORT(x) do { } while (0)
#endif
#define nullptr 0
    
static PRDescIdentity uIdentity;
static PRIOMethods uMethods;

static int32_t
notImplemented(PRFileDesc *fd, void *aBuf, int32_t aAmount,
               int flags, PRNetAddr *addr, PRIntervalTime to)
{
  DEV_ABORT();
  return -1;
}


static int32_t
uLayerRead(PRFileDesc *fd, void *aBuf, int32_t aAmount)
{
  return fd->methods->recv(fd, aBuf, aAmount, 0, PR_INTERVAL_NO_WAIT);
}

static int32_t
uLayerRecv(PRFileDesc *fd, void *aBuf, int32_t aAmount, int flags, PRIntervalTime to)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);

  int32_t rv = PR_Recv(udp_socket, aBuf, aAmount, flags, to);
PRErrorCode errCode = PR_GetError();
fprintf(stderr, "uLayerRecv res = %d code = %d\n", rv, errCode);

  if (errCode ==  PR_IO_TIMEOUT_ERROR) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
  }
  if (rv != -1) {
    fprintf(stderr,"ulayer recv %d\n", rv);
  }
  return rv;
}

static int32_t
uLayerAvailable(PRFileDesc *fd)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_Available(udp_socket);
}

static int32_t
uLayerWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_Write(udp_socket, aBuf, aAmount);
}

static int32_t
uLayerSend(PRFileDesc *fd, const void *aBuf, int32_t aAmount, int flags, PRIntervalTime to)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_Send(udp_socket, aBuf, aAmount, flags, to);
}

static int32_t
uLayerSendTo(PRFileDesc *fd, const void *aBuf, int32_t aAmount, int flags, const PRNetAddr *addr, PRIntervalTime to)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_SendTo(udp_socket, aBuf, aAmount, flags, addr, to);
}

static PRStatus
uLayerGetSockName(PRFileDesc *fd, PRNetAddr *addr)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return udp_socket->methods->getsockname(udp_socket, addr);
}

static PRStatus
uLayerGetPeerName(PRFileDesc *fd, PRNetAddr *addr)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_GetPeerName(udp_socket, addr);
}

static PRStatus
uLayerGetSocketOption(PRFileDesc *fd, PRSocketOptionData *aOpt)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_GetSocketOption(udp_socket, aOpt);
}

static PRStatus
uLayerSetSocketOption(PRFileDesc *fd, const PRSocketOptionData *aOpt)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_SetSocketOption(udp_socket, aOpt);
}

static PRInt16
uLayerPoll(PRFileDesc *fd, int16_t inflags, int16_t *outflags)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return udp_socket->methods->poll(udp_socket, inflags, outflags);
}

static PRStatus
uClose(PRFileDesc *fd)
{
  fd->dtor(fd);
  return PR_SUCCESS;
}

static void
weakDtor(PRFileDesc *fd)
{
  // do not free the handle associated with secret, this
  // layer is just a weak pointer
  fd->secret = nullptr;
  PR_DELETE(fd);
}


static int uLayer_once = 0;
void
uLayer_ensureInit()
{
  // this function is not locked
  if (uLayer_once) {
    return;
  }
  uLayer_once = 1;

  uIdentity = PR_GetUniqueIdentity("udp-uShimLayer");

  uMethods = *PR_GetDefaultIOMethods();

  uMethods.read = uLayerRead;
  uMethods.recv = uLayerRecv;
  uMethods.recvfrom = notImplemented;
  uMethods.available = uLayerAvailable;
  uMethods.write = uLayerWrite;
  uMethods.send = uLayerSend;
  uMethods.sendto = uLayerSendTo;
  uMethods.getsockname = uLayerGetSockName;
  uMethods.getpeername = uLayerGetPeerName;
  uMethods.getsocketoption = uLayerGetSocketOption;
  uMethods.setsocketoption = uLayerSetSocketOption;
  uMethods.poll = uLayerPoll;
  uMethods.close = uClose;

}

PRFileDesc *
uLayer_importFD(PRFileDesc *udp_socket)
{
  uLayer_ensureInit();

  PRFileDesc *uLayer = PR_CreateIOLayerStub(uIdentity, &uMethods); // PR_NSPR_IO_LAYER
  uLayer->secret = (struct PRFilePrivate *)udp_socket;
  uLayer->dtor = weakDtor;
//  uLayer->identity = PR_NSPR_IO_LAYER; // CraeteIoLayerStub rejects this
  return uLayer;
}
