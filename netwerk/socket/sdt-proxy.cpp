/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
// this is a badly written proxy for a sdt client that needs tcp on the web
//
// the proxy is a gateway between udp/sdt on the front side and proxiable tcp/h1 on the backside.
// So it is meant to point at a (h1?) proxy such as squid on localhost:3128

#include <assert.h>
#include "key.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include "nss.h"
#include "pk11pub.h"
#include "pkcs12.h"
#include "prerror.h"
#include "sdt.h"
#include "sechash.h"
#include "secmod.h"
#include "secpkcs7.h"
#include "secport.h"
#include "ssl.h"
#include "sslproto.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "prnetdb.h"
#include "uLayer.h"

#define UDP_LISTEN_PORT 5500

// these are the front side dtls server certs
// currently not checked in the client
#define CERTDIR "/tmp/sdt-proxy"
#define CERTNICK "sdt"

#define GWPORT 5300
#define GWHOST 0x7f000001

static int listen_udp_port = UDP_LISTEN_PORT;
static int connect_tcp_port = GWPORT;
static const char *certdir = CERTDIR;
static const char *certnick = CERTNICK;

#define NS_SOCKET_CONNECT_TIMEOUT PR_MillisecondsToInterval(400)

static PRFileDesc *udp = NULL;
static CERTCertificate *cert;
static SECKEYPrivateKey *privKey;

class flowID;
class flowID *flows[30];
int flowCount = 0;

void
LogIO(const char *label, const char *data, uint32_t datalen)
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
             (reinterpret_cast<const uint8_t *>(data))[index]);
    line += 3;
  }
  if (index) {
    *line = 0;
    fprintf(stderr,"%s\n", linebuf);
  }
}

static SECStatus
GreenLightAuth(void* arg, PRFileDesc* fd, PRBool arg2, PRBool arg3)
{
  // todo integrate with psm
  return SECSuccess;
}

class flowID
{
public:
  flowID(PRNetAddr *addr)
  : tcp(NULL)
  , bufSDT2TCPLen(0)
  , bufTCP2SDTLen(0)
  , mTCPConnected(false)
  {
    if (addr->raw.family == AF_INET) {
      mPort = addr->inet.port;
      mClearTextPayloadSize = SDT_CLEARTEXTPAYLOADSIZE_IPV4;
    } else if (addr->raw.family == AF_INET6) {
      mPort = addr->ipv6.port;
      mClearTextPayloadSize = SDT_CLEARTEXTPAYLOADSIZE_IPV6;
    }

    // layerU needs to be created for each flow and it needs handlers that write to the real udp_socket
    // cannot use udp_socket directly as it can't live in 2 prfiledescs simultaneously (close issues)
    PRFileDesc *layerU = uLayer_importFD(udp);
    assert(layerU);

    sdt_ensureInit();

    sdt = sdt_addSDTLayers(layerU);

    if (!sdt) {
      return;
    }

    sdt = DTLS_ImportFD(NULL,sdt);
    if (!sdt) {
       assert(0);
    }

    bool initOK = true;

    SSLKEAType certKEA = NSS_FindCertKEAType(cert);
    if (SSL_ConfigSecureServer(sdt, cert, privKey, certKEA)
      != SECSuccess) {
      initOK = false;
    }

    SECStatus status;
    status = SSL_OptionSet(sdt, SSL_SECURITY, true);
    if (status != SECSuccess) {
      initOK = false;
    }
    status = SSL_OptionSet(sdt, SSL_HANDSHAKE_AS_CLIENT, false);
    if (status != SECSuccess) {
      initOK = false;
    }
    status = SSL_OptionSet(sdt, SSL_HANDSHAKE_AS_SERVER, true);
    if (status != SECSuccess) {
      initOK = false;
    }
    status = SSL_ResetHandshake(sdt, true);
    if (status != SECSuccess) {
      initOK = false;
    }

    unsigned char npnList[] = "\003h2s";
    if (SSL_SetNextProtoNego(sdt, npnList, 4) != SECSuccess) {
      assert(0);
    }

    if (SSL_OptionSet(sdt, SSL_ENABLE_ALPN, PR_TRUE) != SECSuccess) {
      assert(0);
    }

    sdt = sdt_addALayer(sdt);
    if (!sdt) {
      assert(0);
    }

    PR_Connect(sdt, addr, NS_SOCKET_CONNECT_TIMEOUT);

    if (!initOK) {
      PR_Close(sdt);
      sdt = NULL;
    }
  }

  ~flowID() {
    if (tcp) {
      PR_Close (tcp);
    }
    if (sdt) {
      PR_Close(sdt);
    }
  }

  void connectTCP()
  {
    if (tcp) {
      return;
    }

    tcp = PR_OpenTCPSocket(AF_INET);
    if (!tcp) {
      fprintf(stderr, "tcp: opening socket failed\n");
    } else {
      fprintf(stderr, "tcp: socket opened\n");
    }

    PRStatus status;
    PRSocketOptionData opt;
    opt.option = PR_SockOpt_Nonblocking;
    opt.value.non_blocking = true;
    status = PR_SetSocketOption(tcp, &opt);
    if (status != PR_SUCCESS) {
      PR_Close(tcp);
      tcp = NULL;
    }

    tcp = SSL_ImportFD(NULL, tcp);
    if (!tcp) {
      assert(0);
    }
    if (SSL_AuthCertificateHook(tcp, GreenLightAuth, NULL) != SECSuccess) {
      assert(0);
    }

    SECStatus secStatus;

    secStatus = SSL_SetURL(tcp, "localhost");
    if (secStatus != SECSuccess) {
      assert(0);
    }

    unsigned char npnList[] = "\bhttp/1.1\002h2\bspdy/3.1";
    if (SSL_SetNextProtoNego(tcp, npnList, 21) != SECSuccess) {
      assert(0);
    }

    if (SSL_OptionSet(tcp, SSL_ENABLE_ALPN, PR_TRUE) != SECSuccess) {
      assert(0);
    }
  }

  void ensureConnected()
  {
    if (mTCPConnected) {
      return;
    }

    PRStatus status;
    PRNetAddr addr;
    addr.inet.family = AF_INET;
    addr.inet.port = htons(connect_tcp_port);
    addr.inet.ip = htonl(GWHOST);

    status = PR_Connect(tcp, &addr, NS_SOCKET_CONNECT_TIMEOUT);
    if (status != PR_SUCCESS) {
      PRErrorCode errCode = PR_GetError();
      if (PR_IS_CONNECTED_ERROR == errCode) {
        mTCPConnected = true;
        fprintf(stderr, "TCP - It is connected\n");
      } else if ((PR_WOULD_BLOCK_ERROR == errCode) ||
                 (PR_IN_PROGRESS_ERROR == errCode) ||
                 (PR_NOT_CONNECTED_ERROR == errCode)) {
        PRPollDesc pollElem;
        pollElem.fd = tcp;
        pollElem.in_flags = PR_POLL_WRITE | PR_POLL_EXCEPT;
        fprintf(stderr, "TCP - Poll for a connection.\n");
        while (1) {
          pollElem.out_flags = 0;
          PR_Poll(&pollElem, 1, PR_INTERVAL_NO_WAIT);
          if ( pollElem.out_flags & PR_POLL_WRITE ) {
            fprintf(stderr, "TCP - Connected.\n");
            mTCPConnected = true;
            break;
          } else if (pollElem.out_flags &
                     (PR_POLL_ERR | PR_POLL_HUP | PR_POLL_NVAL)) {
            PRErrorCode errCode = PR_GetError();

            if ((PR_WOULD_BLOCK_ERROR == errCode) ||
                (PR_IN_PROGRESS_ERROR == errCode) ||
                (PR_NOT_CONNECTED_ERROR == errCode)) {
              continue;
            }
            fprintf(stderr, "TCP - Could not connect. error=%d\n", errCode);
            PR_Close(tcp);
            tcp = NULL;
            return;
          }
        }
      } else {
        PR_Close(tcp);
        tcp = NULL;
      }
    }
  }

  // returns: -1 on error (a non would_block error),
  //          otherwise buffer length
  int readSDT()
  {
    if (bufSDT2TCPLen < mClearTextPayloadSize) {
      int read = PR_Read(sdt,
                         bufSDT2TCP + bufSDT2TCPLen,
                         mClearTextPayloadSize - bufSDT2TCPLen);
      if (read < 1) {
        PRErrorCode code = PR_GetError();
        if (code && (code != PR_WOULD_BLOCK_ERROR)) {
          return -1;
        }
      } else {
        bufSDT2TCPLen += read;
        LogIO("SDT read", bufSDT2TCP, bufSDT2TCPLen);
      }
    }
    return bufSDT2TCPLen;
  }

  // returns: -1 on error (non would_block error),
  //          otherwise buffer length
  int readTCP()
  {
    if (bufTCP2SDTLen < mClearTextPayloadSize) {
      int read = PR_Read(tcp, bufTCP2SDT + bufTCP2SDTLen,
                         mClearTextPayloadSize - bufTCP2SDTLen);
      if (read < 1) {
        PRErrorCode code = PR_GetError();
        if ((code != PR_WOULD_BLOCK_ERROR)) {
          return -1;
        }
      } else {
        bufTCP2SDTLen += read;
        LogIO("TCP read", bufTCP2SDT, bufTCP2SDTLen);
      }
    }
    return bufTCP2SDTLen;
  }

  // returns: -1 on error (non would_block error),
  //          oterwise buffer length
  int writeSDT()
  {
    int written = PR_Write(sdt, bufTCP2SDT, bufTCP2SDTLen);
    if (written < 0) {
      PRErrorCode code = PR_GetError();
      if (code != PR_WOULD_BLOCK_ERROR) {
        return -1;
      }
    } else {
      if (written < bufTCP2SDTLen) {
        memmove(bufTCP2SDT, bufTCP2SDT + written, bufTCP2SDTLen - written);
      }
      bufTCP2SDTLen -= written;
      LogIO("SDT write", bufTCP2SDT, bufTCP2SDTLen);
    }
    return bufTCP2SDTLen;
  }

  // returns: -1 on error (non would_block error),
  //          otherwise buffer length
  int writeTCP()
  {
    if (!bufSDT2TCPLen) {
      return 0;
    }
    int written = PR_Write(tcp, bufSDT2TCP, bufSDT2TCPLen);
    if (written < 0) {
      PRErrorCode code = PR_GetError();
      if ((code != PR_WOULD_BLOCK_ERROR)) {
        return -1;
      }
    } else {
      if (written < bufSDT2TCPLen) {
        memmove(bufSDT2TCP, bufSDT2TCP + written, bufSDT2TCPLen - written);
      }
      bufSDT2TCPLen -= written;
      LogIO("T write", bufSDT2TCP, bufSDT2TCPLen);
    }
    return bufSDT2TCPLen;
  }

  uint16_t getTimeout() {
    return sdt_GetNextTimer(sdt);
  }

  PRFileDesc *sdt;
  int mPort;
  PRFileDesc *tcp; // tcp file descriptor
  char bufSDT2TCP[SDT_CLEARTEXTPAYLOADSIZE_MAX];
  int bufSDT2TCPLen;
  char bufTCP2SDT[SDT_CLEARTEXTPAYLOADSIZE_MAX];
  int bufTCP2SDTLen;
  int mClearTextPayloadSize;
  bool mTCPConnected;
};

void
removeAllFlows()
{
  for (int i = 0; i < flowCount; i++) {
    delete flows[i];
    flows[i] = NULL;
  }
}

int
findFlow(const PRNetAddr *addr)
{
  int port;
  if (addr->raw.family == AF_INET) {
    port = addr->inet.port;
  } else if (addr->raw.family == AF_INET6) {
    port = addr->ipv6.port;
  }

  for (int i = 0; i < flowCount; i++) {
    if (flows[i]->mPort == port) {
      return i;
    }
  }

  return -1;
}

// bogus password func, just don't use passwords. :-P
static char *
password_func(PK11SlotInfo* slot, PRBool retry, void* arg)
{
  if (retry) {
    return NULL;
  }
  return strdup("");
}

static void setupNSS()
{
  PK11_SetPasswordFunc(password_func);
  NSS_GetVersion();
  SECStatus status = NSS_Init(certdir);

  if(status != SECSuccess) {
    fprintf(stderr, "NSS_Init() returned %d\n", status);
    assert(false);
  }
  if (NSS_SetDomesticPolicy() != SECSuccess) {
    assert(false);
  }
  if (SSL_ConfigServerSessionIDCache(0, 0, 0, NULL) != SECSuccess) {
    assert(false);
  }

  cert = PK11_FindCertFromNickname(certnick, NULL);
  assert(cert);
  privKey =  PK11_FindKeyByAnyCert(cert, NULL);
  assert(privKey);
}

PRNetAddr sin;

static void
setupListener()
{

  sin.inet.family = PR_AF_INET;
  sin.inet.ip = 0;
  sin.inet.port = htons(listen_udp_port);

  udp = PR_OpenUDPSocket(PR_AF_INET);
  if (udp <= 0) {
     assert(0);
  }

  if (PR_Bind(udp, &sin) != PR_SUCCESS) {
    PR_Close(udp);
    udp = NULL;
  }
}

int main(int argc, char **argv)
{
  if (argc > 1) {
    int i = 1;
    while (i < (argc-1)) {
      if (!strcmp("--udp", argv[i])) {
        listen_udp_port = atoi(argv[i+1]);
        i += 2;
      } else if (!strcmp("--tcp", argv[i])) {
        connect_tcp_port = atoi(argv[i+1]);
        i += 2;
      } else if (!strcmp("--certdir", argv[i])) {
        certdir = argv[i+1];
        i += 2;
      } else if (!strcmp("--certnick", argv[i])) {
        certnick = argv[i+1];
        i += 2;
      } else
        break;
    }
    if (i < argc) {
      printf("sdt-proxy [options]\n"
             "  --udp [port]      UDP port to listen to\n"
             "  --tcp port]       TCP port to connect to\n"
             "  --certdir [path]  Path to the NSS cert directory\n"
             "  --certnick [name] Nick of cert to use\n");
      exit(0);
    }
  }
  printf("Listens to UDP port: %d\n"
         "Connects to TCP port: %d\n"
         "cert directory: %s\n"
         "cert nick: %s\n",
         listen_udp_port, connect_tcp_port, certdir, certnick);

  setupNSS();
  setupListener();

  PRPollDesc pollElem[61];
  pollElem[0].fd = udp;
  pollElem[0].in_flags = PR_POLL_READ | PR_POLL_WRITE | PR_POLL_EXCEPT;

  char udpBuf[SDT_CLEARTEXTPAYLOADSIZE_MAX];
  uint16_t timer;
  while (1) {
    timer = UINT16_MAX;
    pollElem[0].out_flags = 0;
    for (int i = 0; i < flowCount; i++) {
      pollElem[i + 1].out_flags = 0;
      uint16_t t = flows[i]->getTimeout();
      if (timer > t) {
        timer = t;
      }
    }
    int rv;
    rv = PR_Poll(pollElem, flowCount + 1, timer);
    if (rv < 0) {
      fprintf(stderr, "%d Poll error\n", PR_IntervalNow());
      removeAllFlows();
      if (udp) {
        PR_Close(udp);
      }
      return 1;
    }
    if (pollElem[0].out_flags & (PR_POLL_ERR | PR_POLL_HUP | PR_POLL_NVAL)) {
      PRErrorCode errCode = PR_GetError();
      fprintf(stderr, "UDP - Connection error\n");
      if (udp && !(pollElem[0].out_flags & PR_POLL_NVAL)) {
        PR_Close(udp);
      }
      removeAllFlows();
      return 1;
    }

    if ((pollElem[0].out_flags & PR_POLL_READ)) {
      PRNetAddr peerAddr;
      PR_RecvFrom(udp, udpBuf, 1, PR_MSG_PEEK, &peerAddr, PR_INTERVAL_NO_TIMEOUT);

      int flow = findFlow(&peerAddr);
      if ((flow < 0) && flowCount < 30) {
        flows[flowCount] = new flowID(&peerAddr);
        if (flows[flowCount]) {
          flow = flowCount;
          pollElem[flowCount + 1].fd = NULL;
          pollElem[flowCount + 1].in_flags = 0; //PR_POLL_READ | PR_POLL_EXCEPT;
          pollElem[flowCount + 1].out_flags = 0;
          flowCount++;
          int port = 0;
          if (peerAddr.raw.family == AF_INET) {
            port = peerAddr.inet.port;
          } else if (peerAddr.raw.family == AF_INET6) {
            port = peerAddr.ipv6.port;
          }
          fprintf(stderr, "PEER port: %d\n", port);
          char host[164] = {0};
          PR_NetAddrToString(&peerAddr, host, sizeof(host));
          fprintf(stderr, "Peer: %s\n", host);
        }
      }

      if (flow < 0) {
        // remove packet.
        PR_RecvFrom(udp, udpBuf, SDT_CLEARTEXTPAYLOADSIZE_MAX, 0, &peerAddr, PR_INTERVAL_NO_TIMEOUT);
      } else {
        int read = flows[flow]->readSDT();
        if (read < 0) {
          delete flows[flow];
          for (int inx = flow; inx < flowCount - 1; inx++) {
            pollElem[inx + 1] = pollElem[inx + 2];
            flows[inx] = flows[inx + 1];
          }
          flowCount--;
        } else if (read > 0) {
          if (!flows[flow]->tcp) {
            flows[flow]->connectTCP();
            flows[flow]->ensureConnected();
            if (!flows[flow]->tcp) {
              delete flows[flow];
              for (int inx = flow; inx < flowCount - 1; inx++) {
                pollElem[inx + 1] = pollElem[inx + 2];
                flows[inx] = flows[inx + 1];
              }
              flowCount--;
            } else {
              pollElem[flow + 1].fd = flows[flow]->tcp;
              pollElem[flow + 1].in_flags = PR_POLL_READ | PR_POLL_WRITE |
                                            PR_POLL_EXCEPT;
              pollElem[flow + 1].out_flags = 0;
            }
          } else {
            pollElem[flow + 1].in_flags |= PR_POLL_WRITE;
          }
        }
      }
    }

    int i = 0;
    if ((pollElem[0].out_flags & PR_POLL_WRITE)) {
      // TODO change this. This is in my next iteration.
      while (i < flowCount) {
        int written = flows[i]->writeSDT();
        if (written < 0) {
          delete flows[i];
          for (int inx = i; inx < flowCount - 1; inx++) {
            pollElem[inx + 1] = pollElem[inx + 2];
            flows[inx] = flows[inx + 1];
          }
          flowCount--;
          continue;
        } else if (written < flows[i]->mClearTextPayloadSize) {
          pollElem[i + 1].in_flags |= PR_POLL_READ;
        }
        i++;
      }
    }

    i = 0;
    while (i < flowCount) {
      if ((pollElem[i + 1].out_flags & PR_POLL_READ)) {
        int read = flows[i]->readTCP();
        if (read < 0) {
          delete flows[i];
          for (int inx = i; inx < flowCount - 1; inx++) {
            pollElem[inx + 1] = pollElem[inx + 2];
            flows[inx] = flows[inx + 1];
          }
          flowCount--;
          continue;
        } else if (read == flows[i]->mClearTextPayloadSize) {
          pollElem[i + 1].in_flags &= ~PR_POLL_READ; // buffer is full
        }
      }

      if (pollElem[i + 1].out_flags & PR_POLL_WRITE) {
        int written = flows[i]->writeTCP();
//fprintf(stderr, "flows[i]->writeTCP() %d\n", written);
        if (written < 0) {
          delete flows[i];
          for (int inx = i; inx < flowCount - 1; inx++) {
            pollElem[inx + 1] = pollElem[inx + 2];
            flows[inx] = flows[inx + 1];
          }
          flowCount--;
          continue;
        } else if (written == 0) {
          pollElem[i + 1].in_flags &= ~PR_POLL_WRITE;
        }
      }

      if (pollElem[i + 1].out_flags & (PR_POLL_ERR | PR_POLL_HUP | PR_POLL_NVAL)) {
fprintf(stderr, "poll error tcp!!!");
        if (!(pollElem[i + 1].out_flags & PR_POLL_NVAL)) {
          if (flows[i]->tcp) {
            PR_Close(flows[i]->tcp);
            flows[i]->tcp = NULL;
          }
        }
        if (flows[i]->sdt) {
          PR_Close(flows[i]->sdt);
          flows[i]->sdt = NULL;
        }
        delete flows[i];
        for (int inx = i; inx < flowCount - 1; inx++) {
          pollElem[inx + 1] = pollElem[inx + 2];
          flows[inx] = flows[inx + 1];
        }
        flowCount--;
        continue;
      }
      i++;
    }
  }
  return 0;
}
