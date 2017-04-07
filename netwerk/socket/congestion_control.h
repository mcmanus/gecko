/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef CONGESTION_CONTROL_H
#define CONGESTION_CONTROL_H

#define TCP_CA_NAME_MAX 16

#include <stdint.h>
#include "prinrval.h"

struct sdt_t;
struct tcp_general_struct;

struct tcp_congestion_ops {

  void (*Init) (struct sdt_t *sdt);
  void (*OnPacketSent) (struct sdt_t *sdt, uint32_t packetId,
                        uint32_t packetSize);
  void (*OnPacketAcked) (struct sdt_t *sdt, uint32_t packetId,
                         uint32_t smallestUnacked,
                         uint32_t packetSize, PRIntervalTime rtt,
                         uint8_t hasRtt);
  void (*OnPacketLost) (struct sdt_t *sdt, uint32_t packetId,
                        uint32_t packetSize);
  void (*OnRetransmissionTimeout) (struct sdt_t *sdt);
  void (*UndoCwnd) (struct sdt_t *sdt);
  uint8_t (*CanSend) (struct sdt_t *sdt);
};

struct tcp_congestion_variant_ops {
  void (*Init) (struct tcp_general_struct *tcp_g);
  uint32_t (*OnPacketAcked) (struct tcp_general_struct *tcp_g,
                             uint32_t packetId);
  uint32_t (*OnPacketLost) (struct tcp_general_struct *tcp_g);
  void (*OnRetransmissionTimeout) (struct tcp_general_struct *tcp_g);
  void (*OnSendAfterIdle) (struct tcp_general_struct *tcp_g);
};

struct tcp_congestion_slowstart_variant_ops {
  void (*Init) (struct tcp_general_struct *tcp_g);
  uint32_t (*OnPacketAcked) (struct tcp_general_struct *tcp_g,
                             uint32_t packetId, PRIntervalTime rtt);
  void (*OnRetransmissionTimeout) (struct tcp_general_struct *tcp_g);
};

#endif // CONGESTION_CONTROL_H
