/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include <stdio.h>
#include <assert.h>
#include "tcp_general.h"
#include "tcp_cubic.h"
#include "sdt.h"

static struct sdt_congestion_control_variation_ops *cc;
static struct sdt_slowstart_variation_ops *slowstart;
static int8_t sdt_cc_variant_initialized = 0;

static int initial_ssthresh = 0x7fffffff;
#define TCP_IW 10
#define TCP_SLOW_START_AFTER_IDLE 1

#define TCP_GENERAL_MSS 1400

void
init_cc_variant()
{
  if (!sdt_cc_variant_initialized) {
    sdt_cc_variant_initialized = 1;
    cc = &cubic_cc;
    slowstart = &hystart;
  }
}

void
sdt_cc_Init(struct sdt_cc_t *ccData)
{
  init_cc_variant();
  ccData->bytes_in_flight = 0;
  ccData->packets_in_flight = 0;
  ccData->last_sent = 0;
  ccData->last_time_sent = 0;
  ccData->largest_ack = 0;
  ccData->snd_cwnd = TCP_IW;
  ccData->cwnd_cnt = 0;
  ccData->snd_ssthresh = initial_ssthresh;
  ccData->rtt_min = 0;
  ccData->snd_prior_cwnd = 0;
  ccData->snd_prior_ssthresh = 0;
  ccData->waitForRetransmit = 0;
  ccData->last_packet_sent_at_loss_event = 0;
  cc->Init(&ccData->cc_data);
  slowstart->Init(&ccData->cc_data, ccData);
}

uint8_t
sdt_cc_in_recovery(struct sdt_cc_t *ccData,
                       uint64_t smallestUnacked)
{
  return ccData->last_packet_sent_at_loss_event &&
         smallestUnacked <= ccData->last_packet_sent_at_loss_event;
}

uint8_t
sdt_cc_is_cwnd_limited(struct sdt_cc_t *ccData)
{
  if (ccData->snd_cwnd < ccData->snd_ssthresh) {
//    return ca->snd_cwnd * TCP_GENERAL_MSS < 2 * ca->bytes_in_flight;
    return ccData->snd_cwnd < 2 * ccData->packets_in_flight;
  }

//  return ca->bytes_in_flight + TCP_GENERAL_MSS > ca->snd_cwnd * TCP_GENERAL_MSS;
  return ccData->packets_in_flight + 1 > ccData->snd_cwnd;
}

void
sdt_cc_OnPacketSent(struct sdt_cc_t *ccData,
                        uint32_t packetId,
                        uint32_t packetSize)
{
  fprintf(stderr, "sdt_cc_OnPacketSent %d\n", packetId);
  assert(ccData->last_sent < packetId);

  if (!ccData->bytes_in_flight) {
    cc->OnSendAfterIdle(&ccData->cc_data, ccData);
  }

  ccData->last_sent = packetId;
  PRIntervalTime now = PR_IntervalNow();
  ccData->last_time_sent = now;
  ccData->bytes_in_flight += packetSize;
  ccData->packets_in_flight++;
  if (ccData->waitForRetransmit) {
    ccData->waitForRetransmit = 0;
    ccData->snd_cwnd = ccData->snd_ssthresh;
  }
}

void
sdt_cc_OnPacketAcked(struct sdt_cc_t *ccData,
                         uint32_t packetId,
                         uint32_t smallestUnacked,
                         uint32_t packetSize, PRIntervalTime rtt,
                         uint8_t hasRtt) // hasRtt needed because we need to differentiate between not existing rtt and 0 value.
{
  assert(ccData->bytes_in_flight >= packetSize);

  if (hasRtt && ((ccData->largest_ack == 0) || ccData->rtt_min > rtt)) {
    ccData->rtt_min = rtt;
  }

  assert(ccData->last_sent >= packetId);
  if (packetId > ccData->largest_ack) {
    ccData->largest_ack = packetId;
  }

  if (sdt_cc_in_recovery(ccData, smallestUnacked)) {
    ccData->bytes_in_flight -= packetSize;
    ccData->packets_in_flight--;
    return;
  }

  if (sdt_cc_is_cwnd_limited(ccData)) {
    if (ccData->snd_cwnd < ccData->snd_ssthresh) {
      if (hasRtt) {
        ccData->snd_ssthresh = slowstart->OnPacketAcked(&ccData->cc_data,
                                                        ccData,
                                                        packetId, rtt);
      }
      if (ccData->snd_cwnd < ccData->snd_ssthresh) {
        ccData->snd_cwnd++;
      }
    } else {
      uint32_t cnt = cc->OnPacketAcked(&ccData->cc_data, ccData,
                                       packetId);
      if (cnt) {
        if (ccData->cwnd_cnt >= cnt) {
          ccData->cwnd_cnt = 0;
          ccData->snd_cwnd++;
        }
        ccData->cwnd_cnt++;
        if (ccData->cwnd_cnt >= cnt) {
          uint32_t delta = ccData->cwnd_cnt / cnt;
          ccData->cwnd_cnt -= delta * cnt;
          ccData->snd_cwnd += delta;
        }
      } else {
        ccData->cwnd_cnt++;
      }
    }
  }

  ccData->bytes_in_flight -= packetSize;
  ccData->packets_in_flight--;
}

void
sdt_cc_OnPacketLost(struct sdt_cc_t *ccData, uint32_t packetId,
                         uint32_t packetSize)
{
  fprintf(stderr, "sdt_cc_OnPacketLost\n");

  if (packetId > ccData->last_packet_sent_at_loss_event) {
    ccData->snd_prior_cwnd = ccData->snd_cwnd;
    ccData->snd_prior_ssthresh = ccData->snd_ssthresh;
    ccData->last_packet_sent_at_loss_event = ccData->last_sent;
    ccData->snd_ssthresh = cc->OnPacketLost(&ccData->cc_data,
                                                  ccData);
    ccData->waitForRetransmit = packetId;
  }

  ccData->bytes_in_flight -= packetSize;
  ccData->packets_in_flight--;
}

void
sdt_cc_OnRetransmissionTimeout(struct sdt_cc_t *ccData)
{
  ccData->snd_prior_cwnd = ccData->snd_cwnd;
  ccData->snd_prior_ssthresh = ccData->snd_ssthresh;
  ccData->last_packet_sent_at_loss_event = 0;
  slowstart->OnRetransmissionTimeout(&ccData->cc_data,
                                     ccData);
  ccData->snd_ssthresh = ((ccData->bytes_in_flight + TCP_GENERAL_MSS - 1) / TCP_GENERAL_MSS) >> 1;
  ccData->snd_ssthresh = (ccData->snd_ssthresh > 2) ? ccData->snd_ssthresh : 2;
  ccData->bytes_in_flight = 0;
  ccData->packets_in_flight = 0;
}

void
sdt_cc_UndoCwnd (struct sdt_cc_t *ccData)
{
  if (ccData->snd_prior_ssthresh) {
    if (ccData->snd_prior_ssthresh > ccData->snd_ssthresh) {
      ccData->snd_ssthresh = ccData->snd_prior_ssthresh;
    }
    if (ccData->snd_prior_cwnd > ccData->snd_cwnd) {
      ccData->snd_cwnd = ccData->snd_prior_cwnd;
    }
  }
}

uint8_t
sdt_cc_CanSend(struct sdt_cc_t *ccData)
{
  fprintf(stderr, "sdt_cc_CanSend %d %d %d \n",
          ccData->bytes_in_flight, ccData->packets_in_flight,
          ccData->snd_cwnd * TCP_GENERAL_MSS);
//  return (ca->bytes_in_flight + TCP_GENERAL_MSS) <=
//         (ca->snd_cwnd * TCP_GENERAL_MSS);
  return ccData->packets_in_flight < ccData->snd_cwnd;
}

uint32_t
sdt_cc_last_sent(struct sdt_cc_t *ccData)
{
  return ccData->last_sent;
}

uint32_t
sdt_cc_snd_cwnd(struct sdt_cc_t *ccData)
{
  return ccData->snd_cwnd;
}

uint32_t
sdt_cc_packets_in_flight(struct sdt_cc_t *ccData)
{
  return (ccData->bytes_in_flight + TCP_GENERAL_MSS - 1) /
         TCP_GENERAL_MSS;
}

uint32_t
sdt_cc_snd_ssthresh(struct sdt_cc_t *ccData)
{
  return ccData->snd_ssthresh;
}

PRIntervalTime
sdt_cc_last_time_sent(struct sdt_cc_t *ccData)
{
  return ccData->last_time_sent;
}

PRIntervalTime
sdt_cc_rtt_min(struct sdt_cc_t *ccData)
{
  return ccData->rtt_min;
}

struct sdt_congestion_control_ops sdt_cc = {
  .Init = sdt_cc_Init,
  .OnPacketSent = sdt_cc_OnPacketSent,
  .OnPacketAcked = sdt_cc_OnPacketAcked,
  .OnPacketLost = sdt_cc_OnPacketLost,
  .OnRetransmissionTimeout = sdt_cc_OnRetransmissionTimeout,
  .UndoCwnd = sdt_cc_UndoCwnd,
  .CanSend = sdt_cc_CanSend
};
