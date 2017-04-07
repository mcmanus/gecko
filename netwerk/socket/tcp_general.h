/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef TCP_GENERIC_H
#define TCP_GENERIC_H

#include "congestion_control.h"
#include "prinrval.h"
#include <stdint.h>

void tcp_general_Init (struct sdt_t *sdt);
void tcp_general_OnPacketSent (struct sdt_t *sdt, uint32_t packetId,
                               uint32_t packetSize);
void tcp_general_OnPacketAcked (struct sdt_t *sdt, uint32_t packetId,
                                uint32_t smallestUnacked,
                                uint32_t packetSize, PRIntervalTime rtt,
                                uint8_t hasRtt);
void tcp_general_OnPacketLost (struct sdt_t *sdt, uint32_t packetId,
                               uint32_t packetSize);
void tcp_general_OnRetransmissionTimeout (struct sdt_t *sdt);
void tcp_general_UndoCwnd (struct sdt_t *sdt);
uint8_t tcp_general_CanSend (struct sdt_t *sdt);

void *tcp_general_cc_data(struct tcp_general_struct *tcp_g);
uint32_t tcp_general_last_sent(struct tcp_general_struct * tcp_g);
uint32_t tcp_general_snd_cwnd(struct tcp_general_struct * tcp_g);
uint32_t tcp_general_packets_in_flight(struct tcp_general_struct * tcp_g);
uint32_t tcp_general_snd_ssthresh(struct tcp_general_struct * tcp_g);
PRIntervalTime tcp_general_last_time_sent(struct tcp_general_struct * tcp_g);
PRIntervalTime tcp_general_rtt_min(struct tcp_general_struct * tcp_g);

extern struct tcp_congestion_ops tcp_general;

#endif // TCP_GENERIC_H
