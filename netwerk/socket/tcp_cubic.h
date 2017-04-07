/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef CUBIC_H
#define CUBIC_H

#include <stdint.h>
#include "prinrval.h"
#include "congestion_control.h"

void cubic_Reset(struct tcp_general_struct *tcp_g);
uint32_t cubic_OnPacketAcked(struct tcp_general_struct *tcp_g,
                             uint32_t packetId);
uint32_t cubic_OnPacketLost(struct tcp_general_struct *tcp_g);
void cubic_OnRetransmissionTimeout(struct tcp_general_struct *tcp_g);
void cubic_OnSendAfterIdle(struct tcp_general_struct *tcp_g);
uint32_t cubic_UndoCwnd(struct tcp_general_struct *tcp_g);

void hystart_Reset(struct tcp_general_struct *tcp_g);
uint32_t hystart_OnPacketAcked(struct tcp_general_struct *tcp_g,
                               uint32_t packetId, PRIntervalTime last_rtt);

extern struct tcp_congestion_variant_ops cubic_cc;

extern struct tcp_congestion_slowstart_variant_ops hystart;

#endif // CUBIC_H
