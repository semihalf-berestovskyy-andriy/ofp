/*
 * Copyright (c) 2017, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef OFP_IPSEC_H
#define OFP_IPSEC_H

#include <odp.h>
#include "api/ofp_types.h"
#include "api/ofp_ipsec_spd.h"
#include "api/ofp_ipsec_sad.h"

/*
 * Initialize IPsec. Must be called in single thread before starting
 * traffic processing and before calling other IPsec functions.
 *
 * max_num_sa is the maximum number of SAs that can exist at a time.
 *
 * compl_queue is the event queue for signaling the completion of
 * asynchronous IPsec operations. Events of type ODP_EVENT_IPSEC_RESULT
 * arriving in that queue must be delivered to OFP through
 * ofp_ipsec_result(). The default event dispatcher does it
 * automatically. If compl_queue is ODP_QUEUE_INVALID, OFP will
 * create a schedulable event queue itself.
 *
 * Returns nonzero on error.
 */
int ofp_ipsec_init_global(uint32_t max_num_sa, odp_queue_t compl_queue);

/*
 * IPsec event processing function.
 *
 * This function must be called for every received event of type
 * ODP_EVENT_IPSEC_RESULT.
 */
void ofp_ipsec_result(odp_event_t ev);

/*
 * Callback function type for SA lifetime expiry and other events.
 *
 * May be called simultaneously by multiple threads. May be called
 * for every packet triggering the callback.
 *
 * The provided SA is valid for the duration of the callback unless
 * the callee takes a new reference to it using ofp_ipsec_sa_ref().
 *
 * The return value indicates in the usual manner if the callee retained
 * the packet or if the caller should drop the packet or continue
 * processing it.
 */
typedef enum ofp_return_code
(*ofp_ipsec_cb_func)(odp_packet_t pkt, ofp_ipsec_sa_handle sa, void *ctx);

typedef struct {
	ofp_ipsec_cb_func func;
	void *ctx;
} ofp_ipsec_cb;
/*
 * Register callback(s) to be called in specific events.
 * Not MT safe with respect to IPsec processing.
 */
void ofp_ipsec_register_callbacks(ofp_ipsec_cb sa_soft_expiry,
				  ofp_ipsec_cb sa_hard_expiry);


enum ofp_ipsec_pkt_flags {
	OFP_IPSEC_INBOUND_DONE = 1,
	OFP_IPSEC_OUTBOUND_DONE = 2
};
void ofp_ipsec_flags_set(odp_packet_t pkt, uint8_t flags);
uint8_t ofp_ipsec_flags(const odp_packet_t pkt);

/*
 * TODO: These are internal to OFP.
 */
enum ofp_return_code ofp_ipsec_output(uint16_t vrf, odp_packet_t pkt);
enum ofp_return_code ofp_esp4_input(odp_packet_t pkt, int off);
enum ofp_return_code ofp_ah4_input(odp_packet_t pkt, int off);

#endif /* OFP_IPSEC_H */
