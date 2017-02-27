/*
 * Copyright (c) 2017, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef OFPI_IPSEC_SAD_H
#define OFPI_IPSEC_SAD_H

#include <odp.h>
#include "api/ofp_types.h"
#include "api/ofp_ipsec.h"

int ofp_ipsec_sad_init_global(uint32_t max_num_sa, odp_queue_t compl_queue);
int ofp_ipsec_sad_term_global(void);

/*
 * Callback from SA iteration. No other functions declared in this file
 * except the getter functions may be called from the callback.
 * The passed SA handle is not valid after the callback returns unless
 * the callee take a new reference to it using ofp_ipsec_sa_ref().
 *
 * Nonzero return value stops iteration.
 */
typedef int (*ofp_ipsec_sa_cb)(ofp_ipsec_sa_handle sa, void *ctx);

/*
 * Iterate through all SAs and call the provided callback function
 */
void ofp_ipsec_sa_iterate(ofp_ipsec_sa_cb cb, void *ctx);

/*
 * Return ODP SA associated with an SA.
 */
odp_ipsec_sa_t ofp_ipsec_sa_get_odp_sa(ofp_ipsec_sa_handle sa);

/*
 * Return the parameters of an SA. The returned pointer has the same
 * life time as the SA.
 */
const ofp_ipsec_sa_param_t *ofp_ipsec_sa_get_param(ofp_ipsec_sa_handle sa);

/*
 * Find an inbound SA based on VRF and SPI. The returned handle
 * stays valid until unreferenced through ofp_ipsec_sa_unref().
 */
ofp_ipsec_sa_handle ofp_ipsec_sa_in_lookup(uint16_t vrf, uint32_t spi);

/*
 * Reference an SA. Memory and other resources will not be freed
 * as long as there is at least one reference to the SA.
 */
void ofp_ipsec_sa_ref(ofp_ipsec_sa_handle sa);

/*
 * Unreference an SA. Memory and other resources will be freed
 * when the last user of a deleted SA calls this function.
 */
void ofp_ipsec_sa_unref(ofp_ipsec_sa_handle sa);

#endif /* OFPI_IPSEC_SAD_H */
