/*
 * Copyright (c) 2017, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef OFP_IPSEC_SPD_H
#define OFP_IPSEC_SPD_H

#include <odp.h>
#include "api/ofp_types.h"
#include "api/ofp_ipsec_sad.h"

typedef struct {
	uint32_t begin;
	uint32_t end;
} ofp_ipsec_addr_range;

typedef struct {
	uint8_t begin;
	uint8_t end;
} ofp_ipsec_proto_range;

typedef struct {
	ofp_ipsec_addr_range src_addr;
	ofp_ipsec_addr_range dst_addr;
	ofp_ipsec_proto_range proto;
	/* TODO: Add the rest of the selectors */
} ofp_ipsec_selectors;

typedef enum {
	OFP_IPSEC_ACTION_BYPASS,
	OFP_IPSEC_ACTION_DISCARD,
	OFP_IPSEC_ACTION_IPSEC
} ofp_ipsec_sp_action;

typedef struct {
	uint16_t vrf;
	uint32_t id;
	uint32_t priority;
	ofp_ipsec_direction direction;
	ofp_ipsec_selectors selectors;
	ofp_ipsec_sp_action action;
	/* TODO: Add the rest of the parameters */
} ofp_ipsec_sp_param;

int ofp_ipsec_spd_init_global(void);

/*
 * Create a SP. The parameter struct can be freed after the call.
 *
 * Returns nonzero on error.
 */
int ofp_ipsec_sp_create(const ofp_ipsec_sp_param *param);

/*
 * Delete a SP.
 */
int ofp_ipsec_sp_destroy(uint16_t vrf, uint32_t id);

/*
 * Associate an SA with an SP. Disassociate the old SA if set.
 *
 * Only one SA associated with an SP for now. With DSCP specific SAs
 * this probably needs to change.
 *
 * Returns nonzero on error.
 */
int ofp_ipsec_sp_set_sa(uint16_t vrf, uint32_t id, ofp_ipsec_sa_handle sa);

/*
 * Get the SA associated with the SP
 */
ofp_ipsec_sa_handle ofp_ipsec_sp_get_sa(uint16_t vrf, uint32_t id);

/*
 * Lookup the outbound policy mathing to a given packet.
 * Returns the action of the policy and for IPSEC actions
 * the associated SA or OFP_IPSEC_SA_INVALID. The returned
 * SA handle must be unreferenced through ofp_ipsec_sa_unref()
 * after use.
 */
ofp_ipsec_sp_action ofp_ipsec_sp_out_lookup(uint16_t vrf, odp_packet_t pkt,
					    ofp_ipsec_sa_handle *sa);

/*
 * Lookup the inbound policy matching to a given packet.
 */
ofp_ipsec_sp_action ofp_ipsec_sp_in_lookup(uint16_t vrf, odp_packet_t pkt);

#endif /* OFP_IPSEC_SPD_H */
