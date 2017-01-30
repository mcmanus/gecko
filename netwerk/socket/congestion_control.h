/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef CONGESTION_CONTROL_H
#define CONGESTION_CONTROL_H

#define TCP_CA_NAME_MAX 16

#include <stdint.h>
#include "prinrval.h"

struct sdt_t;
struct tcp_general_struct;

/* Cubic TCP Parameters */
struct cubic_t
{
  uint32_t cnt; /* increase cwnd by 1 after ACKs */
  uint32_t last_max_cwnd; /* last maximum snd_cwnd */
  uint32_t last_cwnd; /* the last snd_cwnd */
  uint32_t last_time; /* time when updated last_cwnd */
  uint32_t bic_origin_point; /* origin point of bic function */
  uint32_t bic_K; /* time to origin point from the beginning of the current epoch */
  PRIntervalTime epoch_start;	/* beginning of an epoch */
  uint32_t ack_cnt;	/* number of acks */
  uint32_t tcp_cwnd;	/* estimated tcp cwnd */
  uint32_t sample_cnt;	/* number of samples to decide curr_rtt */
  uint32_t found;		/* the exit point is found? */
  PRIntervalTime round_start;	/* beginning of each round */
  uint32_t end_seq;	/* end_seq of the round */
  PRIntervalTime last_ack;	/* last time when the ACK spacing is close */
  uint32_t curr_rtt;	/* the minimum rtt of current round */

#ifdef DEBUG
  // DEBUG
  PRIntervalTime time; // This is time use for tests only!!!!
#endif
};

union sdt_cc_variation_t
{
  struct cubic_t cubic;
};

struct sdt_cc_t {
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
  union sdt_cc_variation_t cc_data;
};

struct sdt_congestion_control_ops {

  void (*Init) (struct sdt_cc_t *ccData);
  void (*OnPacketSent) (struct sdt_cc_t *ccData, uint32_t packetId,
                        uint32_t packetSize);
  void (*OnPacketAcked) (struct sdt_cc_t *ccData, uint32_t packetId,
                         uint32_t smallestUnacked,
                         uint32_t packetSize, PRIntervalTime rtt,
                         uint8_t hasRtt);
  void (*OnPacketLost) (struct sdt_cc_t *ccData, uint32_t packetId,
                        uint32_t packetSize);
  void (*OnRetransmissionTimeout) (struct sdt_cc_t *ccData);
  void (*UndoCwnd) (struct sdt_cc_t *ccData);
  uint8_t (*CanSend) (struct sdt_cc_t *ccData);
};

struct sdt_congestion_control_variation_ops {
  void (*Init) (union sdt_cc_variation_t *cc);
  uint32_t (*OnPacketAcked) (union sdt_cc_variation_t *cc,
                             struct sdt_cc_t *ccData,
                             uint32_t packetId);
  uint32_t (*OnPacketLost) (union sdt_cc_variation_t *cc,
                            struct sdt_cc_t *ccData);
  void (*OnRetransmissionTimeout) (union sdt_cc_variation_t *cc,
                                   struct sdt_cc_t *ccData);
  void (*OnSendAfterIdle) (union sdt_cc_variation_t *cc,
                           struct sdt_cc_t *ccData);
};

struct sdt_slowstart_variation_ops {
  void (*Init) (union sdt_cc_variation_t *cc, struct sdt_cc_t *ccData);
  uint32_t (*OnPacketAcked) (union sdt_cc_variation_t *cc,
                             struct sdt_cc_t *ccData,
                             uint32_t packetId, PRIntervalTime rtt);
  void (*OnRetransmissionTimeout) (union sdt_cc_variation_t *cc,
                                   struct sdt_cc_t *ccData);
};

#endif // CONGESTION_CONTROL_H
