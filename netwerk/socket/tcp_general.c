/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include <stdio.h>
#include <assert.h>
#include "tcp_general.h"
#include "tcp_cubic.h"
#include "sdt.h"

static struct tcp_congestion_variant_ops *cc;
static struct tcp_congestion_slowstart_variant_ops *slowstart;
static int8_t cc_variant_initialized = 0;

static int initial_ssthresh = 0x7fffffff;
#define TCP_IW 10
#define TCP_SLOW_START_AFTER_IDLE 1

#define TCP_GENERAL_MSS 1400

struct tcp_congestion_ops tcp_general = {
  .Init = tcp_general_Init,
  .OnPacketSent = tcp_general_OnPacketSent,
  .OnPacketAcked = tcp_general_OnPacketAcked,
  .OnPacketLost = tcp_general_OnPacketLost,
  .OnRetransmissionTimeout = tcp_general_OnRetransmissionTimeout,
  .UndoCwnd = tcp_general_UndoCwnd,
  .CanSend = tcp_general_CanSend
};

struct tcp_general_struct {
  uint32_t bytes_in_flight;
  uint32_t packets_in_flight; // this is try to count packets :)
  uint32_t last_sent;
  PRIntervalTime last_time_sent;
  uint32_t largest_ack;
  uint32_t snd_cwnd;
  uint32_t cwnd_cnt;
  uint32_t snd_ssthresh;
  uint32_t last_packet_sent_at_loss_event;
  uint32_t rtt_min;
  uint32_t snd_prior_cwnd; // cwnd just before loss.
  uint32_t snd_prior_ssthresh; // ssthresh just before loss.
  uint32_t waitForRetransmit; // packetId of packet to be retransmitted.
  uint32_t cc_private[15];
};

void
init_cc_variant()
{
  if (!cc_variant_initialized) {
    cc_variant_initialized = 1;
    cc = &cubic_cc;
    slowstart = &hystart;
  }
}

void
tcp_general_Init(struct sdt_t *sdt)
{
  init_cc_variant();
  struct tcp_general_struct *ca = sdt_GetCCPrivate(sdt);
  ca->bytes_in_flight = 0;
  ca->packets_in_flight = 0;
  ca->last_sent = 0;
  ca->last_time_sent = 0;
  ca->largest_ack = 0;
  ca->snd_cwnd = TCP_IW;
  ca->cwnd_cnt = 0;
  ca->snd_ssthresh = initial_ssthresh;
  ca->snd_prior_cwnd = 0;
  ca->snd_prior_ssthresh = 0;
  ca->waitForRetransmit = 0;
  cc->Init(ca);
  slowstart->Init(ca);
}

uint8_t
tcp_general_in_recovery(struct tcp_general_struct *ca, uint64_t smallestUnacked)
{
  return ca->last_packet_sent_at_loss_event &&
         smallestUnacked <= ca->last_packet_sent_at_loss_event;
}

uint8_t
tcp_general_is_cwnd_limited(struct tcp_general_struct *ca)
{
  if (ca->snd_cwnd < ca->snd_ssthresh) {
//    return ca->snd_cwnd * TCP_GENERAL_MSS < 2 * ca->bytes_in_flight;
    return ca->snd_cwnd < 2 * ca->packets_in_flight;
  }

//  return ca->bytes_in_flight + TCP_GENERAL_MSS > ca->snd_cwnd * TCP_GENERAL_MSS;
  return ca->packets_in_flight + 1 > ca->snd_cwnd;
}

void
tcp_general_OnPacketSent(struct sdt_t *sdt, uint32_t packetId,
                         uint32_t packetSize)
{
  struct tcp_general_struct *ca = sdt_GetCCPrivate(sdt);
  fprintf(stderr, "tcp_general_OnPacketSent %d\n", packetId);
  assert(ca->last_sent < packetId);

  if (!ca->bytes_in_flight) {
    cc->OnSendAfterIdle(ca);
  }

  ca->last_sent = packetId;
  PRIntervalTime now = PR_IntervalNow();
  ca->last_time_sent = now;
  ca->bytes_in_flight += packetSize;
  ca->packets_in_flight++;
  if (ca->waitForRetransmit) {
    ca->waitForRetransmit = 0;
    ca->snd_cwnd = ca->snd_ssthresh;
  }
}

void
tcp_general_OnPacketAcked(struct sdt_t *sdt, uint32_t packetId,
                          uint32_t smallestUnacked,
                          uint32_t packetSize, PRIntervalTime rtt,
                          uint8_t hasRtt) // hasRtt needed because we need to differentiate between not existing rtt and 0 value.
{
  struct tcp_general_struct *ca = sdt_GetCCPrivate(sdt);

  assert(ca->bytes_in_flight >= packetSize);
  fprintf(stderr, "tcp_general_OnPacketAcked %d %d\n", packetId, rtt);

  if (hasRtt && ((ca->last_sent == 0) || ca->rtt_min > rtt)) {
    ca->rtt_min = rtt;
  }

  assert(ca->last_sent >= packetId);
  if (packetId > ca->largest_ack) {
    ca->largest_ack = packetId;
  }

  if (tcp_general_in_recovery(ca, smallestUnacked)) {
    ca->bytes_in_flight -= packetSize;
    ca->packets_in_flight--;
    return;
  }

  if (tcp_general_is_cwnd_limited(ca)) {
    if (ca->snd_cwnd < ca->snd_ssthresh) {
      if (hasRtt) {
        ca->snd_ssthresh = slowstart->OnPacketAcked(ca, packetId, rtt);
      }
      if (ca->snd_cwnd < ca->snd_ssthresh) {
        ca->snd_cwnd++;
      }
    } else {
      uint32_t cnt = cc->OnPacketAcked(ca, packetId);
      if (cnt) {
        if (ca->cwnd_cnt >= cnt) {
          ca->cwnd_cnt = 0;
          ca->snd_cwnd++;
        }
        ca->cwnd_cnt++;
        if (ca->cwnd_cnt >= cnt) {
          uint32_t delta = ca->cwnd_cnt / cnt;
          ca->cwnd_cnt -= delta * cnt;
          ca->snd_cwnd += delta;
        }
      } else {
        ca->cwnd_cnt++;
      }
    }
  }

  ca->bytes_in_flight -= packetSize;
  ca->packets_in_flight--;
}

void
tcp_general_OnPacketLost(struct sdt_t *sdt, uint32_t packetId,
                         uint32_t packetSize)
{
  fprintf(stderr, "tcp_general_OnPacketLost\n");

  struct tcp_general_struct *ca = sdt_GetCCPrivate(sdt);

  if (packetId > ca->last_packet_sent_at_loss_event) {
    ca->snd_prior_cwnd = ca->snd_cwnd;
    ca->snd_prior_ssthresh = ca->snd_ssthresh;
    ca->last_packet_sent_at_loss_event = ca->last_sent;
    ca->snd_ssthresh = cc->OnPacketLost(ca);
    ca->waitForRetransmit = packetId;
  }

  ca->bytes_in_flight -= packetSize;
  ca->packets_in_flight--;
}

void
tcp_general_OnRetransmissionTimeout(struct sdt_t *sdt)
{
  struct tcp_general_struct *ca = sdt_GetCCPrivate(sdt);
  ca->snd_prior_cwnd = ca->snd_cwnd;
  ca->snd_prior_ssthresh = ca->snd_ssthresh;
  ca->last_packet_sent_at_loss_event = 0;
  slowstart->OnRetransmissionTimeout(ca);
  ca->snd_ssthresh = ((ca->bytes_in_flight + TCP_GENERAL_MSS - 1) / TCP_GENERAL_MSS) >> 1;
  ca->snd_ssthresh = (ca->snd_ssthresh > 2) ? ca->snd_ssthresh : 2;
  ca->bytes_in_flight = 0;
  ca->packets_in_flight = 0;
}

void tcp_general_UndoCwnd (struct sdt_t *sdt)
{
  struct tcp_general_struct *ca = sdt_GetCCPrivate(sdt);
  if (ca->snd_prior_ssthresh) {
    if (ca->snd_prior_ssthresh > ca->snd_ssthresh) {
      ca->snd_ssthresh = ca->snd_prior_ssthresh;
    }
    if (ca->snd_prior_cwnd > ca->snd_cwnd) {
      ca->snd_cwnd = ca->snd_prior_cwnd;
    }
  }
}

uint8_t
tcp_general_CanSend(struct sdt_t *sdt)
{
  struct tcp_general_struct *ca = sdt_GetCCPrivate(sdt);
  fprintf(stderr, "tcp_general_CanSend %d %d %d \n", ca->bytes_in_flight,
          ca->packets_in_flight, ca->snd_cwnd * TCP_GENERAL_MSS);
//  return (ca->bytes_in_flight + TCP_GENERAL_MSS) <=
//         (ca->snd_cwnd * TCP_GENERAL_MSS);
  return ca->packets_in_flight < ca->snd_cwnd;
}

void *
tcp_general_cc_data(struct tcp_general_struct *tcp_g)
{
  return tcp_g->cc_private;
}

uint32_t
tcp_general_last_sent(struct tcp_general_struct * tcp_g)
{
  return tcp_g->last_sent;
}

uint32_t
tcp_general_snd_cwnd(struct tcp_general_struct * tcp_g)
{
  return tcp_g->snd_cwnd;
}

uint32_t
tcp_general_packets_in_flight(struct tcp_general_struct * tcp_g)
{
    return (tcp_g->bytes_in_flight + TCP_GENERAL_MSS - 1) / TCP_GENERAL_MSS;
}

uint32_t
tcp_general_snd_ssthresh(struct tcp_general_struct * tcp_g)
{
  return tcp_g->snd_ssthresh;
}

PRIntervalTime
tcp_general_last_time_sent(struct tcp_general_struct * tcp_g)
{
  return tcp_g->last_time_sent;
}

PRIntervalTime
tcp_general_rtt_min(struct tcp_general_struct * tcp_g)
{
  return tcp_g->rtt_min;
}
