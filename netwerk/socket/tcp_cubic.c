/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

// This is based on cubic implementation in linux

/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of CUBIC TCP in
 * Sangtae Ha, Injong Rhee and Lisong Xu,
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant"
 *  in ACM SIGOPS Operating System Review, July 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf
 *
 * CUBIC integrates a new slow start algorithm, called HyStart.
 * The details of HyStart are presented in
 *  Sangtae Ha and Injong Rhee,
 *  "Taming the Elephants: New TCP Slow Start", NCSU TechReport 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/hystart_techreport_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <stdio.h>
#include "tcp_cubic.h"
#include "tcp_general.h"
#include "prinrval.h"

#define BICTCP_BETA_SCALE 1024 /* Scale factor beta calculation
                                * max_cwnd = snd_cwnd * beta
                                */
#define	BICTCP_HZ 10 /* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN 0x1
#define HYSTART_DELAY 0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES 8

// in the paper the following 2 values are 2 and 8, in linux they are 4 and 16ms
#define HYSTART_DELAY_MIN PR_MillisecondsToInterval(4)
 //(4U<<3)
#define HYSTART_DELAY_MAX PR_MillisecondsToInterval(16)
 //(16U<<3)
#define HYSTART_DELAY_THRESH(x)	({                              \
  uint32_t r = (x < HYSTART_DELAY_MIN) ? HYSTART_DELAY_MIN : x; \
  (r < HYSTART_DELAY_MAX) ? r : HYSTART_DELAY_MAX; })

static int fast_convergence = 1;
#define beta 717
/* = 717/1024 (BICTCP_BETA_SCALE) */
#define bic_scale 41

// HYSTART_ACK_TRAIN with rtt ~ 0 does not work well.
static int hystart_detect = HYSTART_DELAY; // | HYSTART_ACK_TRAIN;
static unsigned int hystart_low_window = 16;
static int hystart_ack_delta = 2;

const uint32_t beta_scale = 8 * (BICTCP_BETA_SCALE+beta) / 3
		                        / (BICTCP_BETA_SCALE - beta);
static uint32_t cube_rtt_scale = 410; //bic_scale * 10;
const uint64_t cube_factor = (1ull << (10+3*BICTCP_HZ)) / (bic_scale * 10);

void
cubic_Reset(union sdt_cc_variation_t *cc)
{
  cc->cubic.cnt = 0;
  cc->cubic.last_max_cwnd = 0;
  cc->cubic.last_cwnd = 0;
  cc->cubic.last_time = 0;
  cc->cubic.bic_origin_point = 0;
  cc->cubic.bic_K = 0;
  cc->cubic.epoch_start = 0;
  cc->cubic.ack_cnt = 0;
  cc->cubic.tcp_cwnd = 0;
  cc->cubic.curr_rtt = 0;
  cc->cubic.found = 0;

#ifdef DEBUG
  cc->cubic.time = 0;
#endif
}

// The next 3 functions are cbrt.
uint32_t
fls64(uint64_t a)
{
  uint32_t b = 63;
  if (!(a & (0xffffffff00000000))) {
    b -= 32;
    a <<= 32;
  }
  if (!(a & (0xffff000000000000))) {
    b -= 16;
    a <<= 16;
  }
  if (!(a & (0xff00000000000000))) {
    b -= 8;
    a <<= 8;
  }
  if (!(a & (0xf000000000000000))) {
    b -= 4;
    a <<= 4;
  }
  if (!(a & (0xc000000000000000))) {
    b -= 2;
    a <<= 2;
  }
  if (!(a & (0x8000000000000000))) {
    b -= 1;
  }
  return b;
}

uint64_t
div64_u64(uint64_t dividend, uint64_t divisor)
{
  uint32_t high = divisor >> 32;
  uint64_t quot;

  if (high == 0) {
    quot = dividend / divisor;
  } else {
    int n = 1 + fls64(high);
    quot = (dividend >> n) / (divisor >> n);

    if (quot != 0)
      quot--;
    if ((dividend - quot * divisor) >= divisor)
      quot++;
    }
    return quot;
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
uint32_t
cubic_root(uint64_t a)
{
  uint32_t x, b, shift;
  /*
   * cbrt(x) MSB values for x MSB values in [0..63].
   * Precomputed then refined by hand - Willy Tarreau
   *
   * For x in [0..63],
   *   v = cbrt(x << 18) - 1
   *   cbrt(x) = (v[x] + 10) >> 6
   */
  static const uint8_t v[] = {
    /* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
    /* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
    /* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
    /* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
    /* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
    /* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
    /* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
    /* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
  };

  b = fls64(a);

  if (b < 7) {
    /* a in [0..63] */
    return ((uint32_t)v[(uint32_t)a] + 35) >> 6;
  }

  b = ((b * 84) >> 8) - 1;
  shift = (a >> (b * 3));

  x = ((uint32_t)(((uint32_t)v[shift] + 10) << b)) >> 6;

  /*
   * Newton-Raphson iteration
   *                         2
   * x    = ( 2 * x  +  a / x  ) / 3
   *  k+1          k         k
   */
  x = (2 * x + (uint32_t)div64_u64(a, (uint64_t)x * (uint64_t)(x - 1)));
  x = ((x * 341) >> 10);
  return x;
}

/*
 * Update cubic values.
 */
void
bictcp_update(struct cubic_t *ca, uint32_t cwnd, PRIntervalTime rtt_min)
{
  uint32_t delta, bic_target, max_cnt;
  uint64_t offs, t;

  ca->ack_cnt++; /* count the number of ACKed packets */

#ifdef DEBUG
  PRIntervalTime now = (ca->time) ? ca->time : PR_IntervalNow();
#else
  PRIntervalTime now = PR_IntervalNow();
#endif

  if (ca->last_cwnd == cwnd &&
      (now - ca->last_time) <= PR_MillisecondsToInterval(30)) {
    return;
  }
  ca->last_cwnd = cwnd;
  ca->last_time = now;

  /* The CUBIC function can update ca->cnt at most once per jiffy.
   * On all cwnd reduction events, ca->epoch_start is set to 0,
   * which will force a recalculation of ca->cnt.
   */
//  if (ca->epoch_start && now == ca->last_time) {
//    goto tcp_friendliness;
//  }
//  ca->last_cwnd = cwnd;
//  ca->last_time = now;

  if (ca->epoch_start == 0) {
    ca->epoch_start = now; /* record beginning */
    ca->ack_cnt = 1; /* start counting */
    ca->tcp_cwnd = cwnd; /* syn with cubic */

    if (ca->last_max_cwnd <= cwnd) {
      ca->bic_K = 0;
      ca->bic_origin_point = cwnd;
    } else {
      /* Compute new K based on
       * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
       */
      ca->bic_K = cubic_root(cube_factor * (ca->last_max_cwnd - cwnd));
      ca->bic_origin_point = ca->last_max_cwnd;
    }
  }

  /* cubic function - calc*/
  /* calculate c * time^3 / rtt,
   *  while considering overflow in calculation of time^3
   * (so time^3 is done by using 64 bit)
   * and without the support of division of 64bit numbers
   * (so all divisions are done by using 32 bit)
   *  also NOTE the unit of those veriables
   *    time  = (t - K) / 2^bictcp_HZ
   *    c = bic_scale >> 10
   *    rtt  = (srtt >> 3) / HZ
   * !!! The following code does not have overflow problems,
   * if the cwnd < 1 million packets !!!
   */

  t = ((uint64_t)(PR_IntervalToMicroseconds(now + rtt_min - ca->epoch_start)) << 10) / 1000000;
  if (t < ca->bic_K) { /* t - K */
    offs = ca->bic_K - t;
  } else {
    offs = t - ca->bic_K;
  }

  /* c/rtt * (t-K)^3 */
  delta = (cube_rtt_scale * offs * offs * offs) >> 40; //(10+3*BICTCP_HZ);
  if (t < ca->bic_K) { /* below origin*/
    bic_target = ca->bic_origin_point - delta;
  } else { /* above origin*/
    bic_target = ca->bic_origin_point + delta + 1;
  }

  /* cubic function - calc bictcp_cnt*/
  if (bic_target > cwnd) {
    ca->cnt = cwnd / (bic_target - cwnd);
  } else {
    ca->cnt = 100 * cwnd; /* very small increment*/
  }

  /*
   * The initial growth of cubic function may be too conservative
   * when the available bandwidth is still unknown.
   */
  if (ca->last_max_cwnd == 0 && ca->cnt > 20) {
    ca->cnt = 20; /* increase cwnd 5% per RTT */
  }

//tcp_friendliness:

  /* TCP Friendly */
  {
    uint32_t scale = beta_scale;

    delta = (cwnd * scale) >> 3;
    while (ca->ack_cnt > delta) { /* update tcp cwnd */
      ca->ack_cnt -= delta;
      ca->tcp_cwnd++;
    }
  }

  if (ca->tcp_cwnd > cwnd) { /* if bic is slower than tcp */
    delta = ca->tcp_cwnd - cwnd;
    max_cnt = cwnd / delta;
    if (ca->cnt > max_cnt) {
      ca->cnt = max_cnt;
    }
  }

  /* The maximum rate of cwnd increase CUBIC allows is 1 packet per
   * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
   */
  ca->cnt = (ca->cnt < 2) ? 2 : ca->cnt;
}

uint32_t
cubic_OnPacketAcked(union sdt_cc_variation_t *cc,
                    struct sdt_cc_t *ccData,
                    uint32_t packetId)
{
  struct cubic_t *ca = &cc->cubic;

  uint32_t cwnd = sdt_cc_snd_cwnd(ccData);

  /* Discard delay samples right after fast recovery */
  // Do update only for (PR_IntervalNow() - ca->epoch_start) >= 10
#ifdef DEBUG
  PRIntervalTime now = (ca->time) ? ca->time : PR_IntervalNow();
#else
  PRIntervalTime now = PR_IntervalNow();
#endif

  if (!ca->epoch_start || (int32_t)(now - ca->epoch_start) >= 10) {
    bictcp_update(ca, cwnd, sdt_cc_rtt_min(ccData));
  }

  return ca->cnt;
}

// loss detected.
uint32_t
cubic_OnPacketLost(union sdt_cc_variation_t *cc,
                   struct sdt_cc_t *ccData)
{
  struct cubic_t *ca = &cc->cubic;
  uint32_t packetsInFilght = sdt_cc_packets_in_flight(ccData);
  ca->epoch_start = 0; /* end of epoch */

  /* Wmax and fast convergence */
  if (packetsInFilght < ca->last_max_cwnd && fast_convergence) {
    ca->last_max_cwnd = (packetsInFilght * (BICTCP_BETA_SCALE + beta))
      / (2 * BICTCP_BETA_SCALE);
  } else {
    ca->last_max_cwnd = packetsInFilght;
  }
  packetsInFilght = (packetsInFilght * beta) / BICTCP_BETA_SCALE;

  return (packetsInFilght < 2U) ? 2 : packetsInFilght;
}

void
cubic_OnSendAfterIdle(union sdt_cc_variation_t *cc,
                      struct sdt_cc_t *ccData)
{
  struct cubic_t *ca = &cc->cubic;

#ifdef DEBUG
  PRIntervalTime now = (ca->time) ? ca->time : PR_IntervalNow();
#else
  PRIntervalTime now = PR_IntervalNow();
#endif

  PRIntervalTime delta;

  delta = now - sdt_cc_last_time_sent(ccData);

  /* We were application limited (idle) for a while.
   * Shift epoch_start to keep cwnd growth to cubic curve.
   */
  if (ca->epoch_start && delta > 0) {
    ca->epoch_start += delta;
    if (ca->epoch_start > now) {
      ca->epoch_start = now;
    }
  }
}

void
hystart_Reset(struct cubic_t *cc, struct sdt_cc_t *ccData)
{
#ifdef DEBUG
  PRIntervalTime now = (cc->time) ? cc->time : PR_IntervalNow();
#else
  PRIntervalTime now = PR_IntervalNow();
#endif

  cc->round_start = cc->last_ack = now;
  cc->end_seq = sdt_cc_last_sent(ccData);
  cc->curr_rtt = 0;
  cc->sample_cnt = 0;
  cc->found = 0;
}

uint32_t
hystart_update(struct cubic_t *ca,
               struct sdt_cc_t *ccData, PRIntervalTime last_rtt)
{
  uint32_t cwnd = sdt_cc_snd_cwnd(ccData);
  uint32_t ssthresh = sdt_cc_snd_ssthresh(ccData);
  uint32_t rtt_min = sdt_cc_rtt_min(ccData);

  if (ca->found & hystart_detect) {
    return ssthresh;
  }

  if (hystart_detect & HYSTART_ACK_TRAIN) {

#ifdef DEBUG
  PRIntervalTime now = (ca->time) ? ca->time : PR_IntervalNow();
#else
  PRIntervalTime now = PR_IntervalNow();
#endif

    /* first detection parameter - ack-train detection */
    if ((int32_t)(now - ca->last_ack) <= (int32_t)PR_MillisecondsToInterval(hystart_ack_delta)) {
      ca->last_ack = now;
      if ((int32_t)(now - ca->round_start) > (int32_t)(rtt_min >> 1)) {
        ca->found |= HYSTART_ACK_TRAIN;
        ssthresh = cwnd;
      }
    }
  }

  if (hystart_detect & HYSTART_DELAY) {
    /* obtain the minimum delay of all sampling packets */
    if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
      if ((ca->sample_cnt == 0) || ca->curr_rtt > last_rtt) {
        ca->curr_rtt = last_rtt;
      }
       ca->sample_cnt++;
       // We need to check this only once per round!!!
      if (ca->sample_cnt == HYSTART_MIN_SAMPLES) {
        // in the paper rtt is devided by 16, but in linux it is 8.
        // also in the paper thay use the last rtt sample instead of rtt_min.
        if (ca->curr_rtt > rtt_min + HYSTART_DELAY_THRESH(rtt_min >> 3)) {
          ca->found |= HYSTART_DELAY;
          ssthresh = cwnd;
        }
      }
    }
  }
  return ssthresh;
}

/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 */
uint32_t
hystart_OnPacketAcked(union sdt_cc_variation_t *cc,
                      struct sdt_cc_t *ccData, uint32_t packetId,
                      PRIntervalTime last_rtt)
{
  struct cubic_t *ca = &cc->cubic;

  uint32_t cwnd = sdt_cc_snd_cwnd(ccData);
  uint32_t ssthresh = sdt_cc_snd_ssthresh(ccData);

  if ((ca->end_seq < packetId)) {
    hystart_Reset(ca, ccData);
  }

  /* hystart triggers when cwnd is larger than some threshold, because i needs
    to sample 8 acks and considdering a delayed ack hystart_low_window is set to
    16. */
  if (cwnd >= hystart_low_window) {
    ssthresh = hystart_update(ca, ccData, last_rtt);
  }
  return ssthresh;
}

struct sdt_congestion_control_variation_ops cubic_cc = {
  .Init = cubic_Reset,
  .OnPacketAcked = cubic_OnPacketAcked,
  .OnPacketLost = cubic_OnPacketLost,
  .OnRetransmissionTimeout = cubic_Reset,
  .OnSendAfterIdle = cubic_OnSendAfterIdle
};

struct sdt_slowstart_variation_ops hystart = {
  .Init = hystart_Reset,
  .OnPacketAcked = hystart_OnPacketAcked,
  .OnRetransmissionTimeout = hystart_Reset
};
