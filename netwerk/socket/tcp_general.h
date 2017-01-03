/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef TCP_GENERIC_H
#define TCP_GENERIC_H

#include "congestion_control.h"
#include "prinrval.h"
#include <stdint.h>

uint32_t sdt_cc_last_sent(struct sdt_cc_t * ccData);
uint32_t sdt_cc_snd_cwnd(struct sdt_cc_t * ccData);
uint32_t sdt_cc_packets_in_flight(struct sdt_cc_t * ccData);
uint32_t sdt_cc_snd_ssthresh(struct sdt_cc_t * ccData);
PRIntervalTime sdt_cc_last_time_sent(struct sdt_cc_t * ccData);
PRIntervalTime sdt_cc_rtt_min(struct sdt_cc_t * ccData);

extern struct sdt_congestion_control_ops sdt_cc;

#endif // TCP_GENERIC_H
