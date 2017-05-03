/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include "DNS.h"
#include "nsNetAddr.h"
#include "nspr.h"
#include "prerror.h"
#include "mozilla/Logging.h"
#include "sdt_common.h"
#include "SDTUpper.h"
#include "QuicLog.h"

namespace mozilla {
namespace net {

SDTUpper::SDTUpper(PRFileDesc *aFd)
  : mFd(aFd)
  , mSocketTransportService(gSocketTransportService)
  , mAttached(false)
  , mUpperFDDetached(false)
  , mByteReadCount(0)
  , mByteWriteCount(0)
  , mError(0)
  , mPollError(0)
{
}

// ============================================================================
// nsASocketHandler
//=============================================================================

void
SDTUpper::IsLocal(bool *aIsLocal)
{
  *aIsLocal = mIsLocal;
}

void
SDTUpper::OnSocketDetached(PRFileDesc *aFd)
{
  LOG(("SDTUpper::OnSocketDetached [this=%p cond=%x]",
       this, mCondition));
  mCondition = NS_ERROR_ABORT;
  if (mUpperFDDetached) {
    Release();
    aFd->secret = nullptr;
    PR_DELETE(aFd);
  }
}

void
SDTUpper::SetUpperFDDetached()
{
  mCondition = NS_ERROR_ABORT;
  mUpperFDDetached = true;
}

int32_t
SDTUpper::ReadData(void *aBuf, int32_t aAmount, int aFlags)
{
 LOG(("SDTUpper::ReadData amount=%d", aAmount));
  if (mError) {
    PR_SetError(mError, 0);
    return -1;
  }
  return PR_Recv(mFd, aBuf, aAmount, aFlags, 0);
}

bool
SDTUpper::HasData()
{
  return sdt_HasData(mFd);
}

bool
SDTUpper::SocketWritable()
{
  return sdt_SocketWritable(mFd);
}

int32_t
SDTUpper::WriteData(const void *aBuf, int32_t aAmount)
{
  LOG(("SDTUpper::WriteData amount=%d", aAmount));
  if (mError) {
    PR_SetError(mError, 0);
    return -1;
  }
  return PR_Write(mFd, aBuf, aAmount);
}

void
SDTUpper::OnSocketReady(PRFileDesc *fd, int16_t outFlags)
{

  LOG(("SDTUpper::OnSocketReady %d %d", outFlags, mError));
  if (mError) {
    return;
  }

  if (outFlags & (PR_POLL_ERR | PR_POLL_NVAL | PR_POLL_HUP)) {
    mPollError = outFlags;
    return;
  }

  if (outFlags == -1) {
    LOG(("SDTUpper::OnSocketReady - socket timeout expired"));
    mCondition = NS_ERROR_NET_TIMEOUT;
    return;
  }

  if (outFlags & ~PR_POLL_READ) {
    int32_t rv = PR_Write(mFd, nullptr, 0);
    if (rv < 0) {
      PRErrorCode errCode = PR_GetError();
      if (errCode != PR_WOULD_BLOCK_ERROR) {
        mError = errCode;
      }
    }
  }

  if (outFlags & ~PR_POLL_WRITE) {
    int32_t rv = sdt_GetData(mFd);
    if (rv < 0) {
      PRErrorCode errCode = PR_GetError();
      if (errCode != PR_WOULD_BLOCK_ERROR) {
        mError = errCode;
      }
    }
  }

  mPollTimeout = sdt_GetNextTimer(mFd);
  mPollFlags = (PR_POLL_READ | PR_POLL_WRITE | PR_POLL_EXCEPT);
}

nsresult
SDTUpper::AttachSocket()
{
  LOG(("SDTUpper::AttachSocket [this=%p]", this));
  nsresult rv = mSocketTransportService->AttachSocket(mFd, this);
  if (NS_SUCCEEDED(rv)) {
    // The nsASocketHandler of the real socket will call PR_Close which will
    // close this socket as well.
    mAttached = true;
    mPollTimeout = sdt_GetNextTimer(mFd);
    mPollFlags = (PR_POLL_READ | PR_POLL_WRITE | PR_POLL_EXCEPT);
  }
  return rv;
}

void
SDTUpper::SetLocal(bool aLocal)
{
  mIsLocal = aLocal;
}

NS_IMPL_ADDREF(SDTUpper)
NS_IMPL_RELEASE(SDTUpper)
NS_INTERFACE_MAP_BEGIN(SDTUpper)
NS_INTERFACE_MAP_END

} // namespace mozilla::net
} // namespace mozilla

static int32_t
sdtUpperLayerRecv(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
                  int aFlags, PRIntervalTime to)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFD->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return -1;
  }

  return handle->ReadData(aBuf, aAmount, aFlags);
}

static int32_t
sdtUpperLayerWrite(PRFileDesc *aFD, const void *aBuf, int32_t aAmount)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFD->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return -1;
  }
  return handle->WriteData(aBuf, aAmount);
}


static PRInt16 PR_CALLBACK
sdtUpperLayerPoll(PRFileDesc *aFd, PRInt16 how_flags, PRInt16 *p_out_flags)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFd->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    *p_out_flags = PR_POLL_ERR;
    return PR_POLL_ERR; // TODO check this.
  }

  *p_out_flags = 0;

  if (handle->GetPollError()) {
    *p_out_flags = handle->GetPollError();
    return  how_flags;
  }

  // If there is an error let it call read/write to pick it up.
  if (handle->IsError()) {
    *p_out_flags = how_flags;
    return how_flags;
  }

  if ((how_flags & PR_POLL_READ) && handle->HasData()) {
    *p_out_flags = PR_POLL_READ;
  }

  if ((how_flags & PR_POLL_WRITE) && handle->SocketWritable()) {
    *p_out_flags = PR_POLL_WRITE;
  }

  return how_flags;
}

static PRStatus
sdtUpperLayerConnect(PRFileDesc *aFd, const PRNetAddr *addr, PRIntervalTime to)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFd->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return PR_FAILURE;
  }
  nsresult rv = handle->AttachSocket();
  if (NS_FAILED(rv)) {
    return PR_FAILURE;
  }

  mozilla::net::NetAddr netAddr;
  PRNetAddrToNetAddr(addr, &netAddr);
  bool local = mozilla::net::IsLoopBackAddress(&netAddr);
  handle->SetLocal(local);
  return PR_Connect(handle->GetLowerFd(), addr, to);
}

static PRStatus
sdtUpperLayerConnectContinue(PRFileDesc *aFd, int16_t oflags)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFd->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return PR_FAILURE;
  }
  return PR_ConnectContinue(handle->GetLowerFd(), oflags);
}

static PRStatus
sdtUpperLayerBind(PRFileDesc *aFd, const PRNetAddr *addr)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFd->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return PR_FAILURE;
  }

  return PR_Bind(handle->GetLowerFd(), addr);
}

static PRStatus
sdtUpperLayerGetSockName(PRFileDesc *aFd, PRNetAddr *addr)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFd->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return PR_FAILURE;
  }
  return PR_GetSockName(handle->GetLowerFd(), addr);
}

static PRStatus
sdtUpperLayerGetPeerName(PRFileDesc *aFd, PRNetAddr *addr)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFd->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return PR_FAILURE;
  }

  return PR_GetPeerName(handle->GetLowerFd(), addr);
}

static PRStatus
sdtUpperLayerGetSocketOption(PRFileDesc *aFd, PRSocketOptionData *aOpt)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFd->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return PR_FAILURE;
  }
  return PR_GetSocketOption(handle->GetLowerFd(), aOpt);
}

static PRStatus
sdtUpperLayerSetSocketOption(PRFileDesc *aFd, const PRSocketOptionData *aOpt)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFd->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return PR_FAILURE;
  }
  return PR_SetSocketOption(handle->GetLowerFd(), aOpt);
}

static void
sdtUpperDtor(PRFileDesc *aFd)
{
  if (aFd->secret) {
    mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFd->secret);
    if (!handle->IsAttached()) {
      NS_RELEASE(handle);
      aFd->secret = nullptr;
      PR_DELETE(aFd);
    } else {
      handle->SetUpperFDDetached();
    }
  } else {
    PR_DELETE(aFd);
  }
}

static PRStatus
sdtUpperLayerClose(PRFileDesc *fd)
{
  fd->dtor(fd);
  return PR_SUCCESS;
}

static PRDescIdentity sdtUpperIdentity;
static PRIOMethods sdtUpperMethods;

namespace mozilla {
namespace net {

static int sdtUpper_once = 0;

void
sdtUpper_ensureInit()
{
  if (sdtUpper_once) {
    return;
  }
  sdtUpper_once = 1;

  sdtUpperIdentity = PR_GetUniqueIdentity("sdtUpperLayer");
  sdtUpperMethods = *PR_GetDefaultIOMethods();

  sdtUpperMethods.read = sdt_useRecv;
  sdtUpperMethods.recv = sdtUpperLayerRecv;
  sdtUpperMethods.recvfrom = sdt_notImplemented;
  sdtUpperMethods.write = sdtUpperLayerWrite;
  sdtUpperMethods.send = sdt_notImplemented2;
  sdtUpperMethods.sendto = sdt_notImplemented3;
  sdtUpperMethods.close = sdtUpperLayerClose;
  sdtUpperMethods.poll = sdtUpperLayerPoll;
  sdtUpperMethods.connect = sdtUpperLayerConnect;
  sdtUpperMethods.connectcontinue = sdtUpperLayerConnectContinue;
  sdtUpperMethods.bind = sdtUpperLayerBind;
  sdtUpperMethods.getsockname = sdtUpperLayerGetSockName;
  sdtUpperMethods.getpeername = sdtUpperLayerGetPeerName;
  sdtUpperMethods.getsocketoption = sdtUpperLayerGetSocketOption;
  sdtUpperMethods.setsocketoption = sdtUpperLayerSetSocketOption;
}

PRFileDesc *
sdt_createSDTSocket(PRFileDesc *aFd)
{
  sdtUpper_ensureInit();

  PRFileDesc *sdtUpperSocket = nullptr;
  mozilla::net::SDTUpper *handle = nullptr;

  if (!(aFd && aFd->secret)) {
    goto fail; // ha!
  }

  sdtUpperSocket = PR_CreateIOLayerStub(sdtUpperIdentity, &sdtUpperMethods);

  if (!sdtUpperSocket) {
    goto fail; // ha!
  }
  sdtUpperSocket->dtor = sdtUpperDtor;

  handle = new mozilla::net::SDTUpper(aFd);
  if (!handle) {
    goto fail;
  }

  NS_ADDREF(handle);

  sdtUpperSocket->secret = (struct PRFilePrivate *)handle;

  return sdtUpperSocket;

fail:
  if (sdtUpperSocket) {
    sdtUpperSocket->dtor(sdtUpperSocket);
  }
  return nullptr;
}

PRFileDesc *
sdt_getSDTFD(PRFileDesc *aFd)
{
  mozilla::net::SDTUpper *handle = (mozilla::net::SDTUpper *)(aFd->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return nullptr;
  }
  return  handle->GetFD();
}

#undef LOG
} // namespace mozilla::net
} // namespace mozilla
