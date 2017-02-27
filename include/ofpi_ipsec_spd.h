/*
 * Copyright (c) 2017, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef OFPI_IPSEC_SPD_H
#define OFPI_IPSEC_SPD_H

#include <odp.h>
#include "api/ofp_types.h"
#include "api/ofp_ipsec.h"
#include "ofpi_ipsec_sad.h"

int ofp_ipsec_spd_init_global(void);

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
ofp_ipsec_action_t ofp_ipsec_sp_out_lookup(uint16_t vrf, odp_packet_t pkt,
					    ofp_ipsec_sa_handle *sa);

/*
 * Lookup the inbound policy matching to a given packet.
 */
ofp_ipsec_action_t ofp_ipsec_sp_in_lookup(uint16_t vrf, odp_packet_t pkt);

#endif /* OFPI_IPSEC_SPD_H */
