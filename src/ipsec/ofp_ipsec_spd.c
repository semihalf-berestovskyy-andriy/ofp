/*
 * Copyright (c) 2017, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include "api/ofp_types.h"
#include "api/ofp_pkt_processing.h"
#include "api/ofp_log.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_shared_mem.h"
#include "ofpi_ipsec_spd.h"
#include "ofpi_ipsec_sad.h"


struct ofp_ipsec_sp {
	ofp_ipsec_sp_param param;
	ofp_ipsec_sa_handle sa;
	odp_ipsec_sa_t odp_sa;
	struct ofp_ipsec_sp *next;
};

struct ofp_ipsec_spd {
	odp_rwlock_t lock;
	struct ofp_ipsec_sp *outbound_sp_list;
	struct ofp_ipsec_sp *inbound_sp_list;
	struct ofp_ipsec_sp *free_sp_list;
};

struct ofp_ipsec_selector_values {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t ip_proto;
	/* TODO: add the rest of the selectors */
};

#define SHM_NAME_IPSEC_SPD "ofp_ipsec_spd"
static __thread struct ofp_ipsec_spd *shm;

int ofp_ipsec_spd_init_global(void)
{
	/* TODO: request identical address mapping across threads */
	shm = ofp_shared_memory_alloc(SHM_NAME_IPSEC_SPD, sizeof(*shm));
	if (!shm) {
		OFP_ERR("Failed to allocate IPsec SPD shared memory");
		return -1;
	}
	memset(shm, 0, sizeof(*shm));
	odp_rwlock_init(&shm->lock);
	return 0;
}

static struct ofp_ipsec_sp *ofp_ipsec_sp_alloc(void)
{
	struct ofp_ipsec_sp *sp;

	sp = shm->free_sp_list;
	if (sp)
		shm->free_sp_list = sp->next;
	return sp;
}

static void ofp_ipsec_sp_free(struct ofp_ipsec_sp *sp)
{
	sp->next = shm->free_sp_list;
	shm->free_sp_list = sp;
}

static struct ofp_ipsec_sp **ofp_ipsec_find_in_list(struct ofp_ipsec_sp **link,
						    uint16_t vrf,
						    uint32_t id)
{
	while (*link) {
		if ((*link)->param.vrf == vrf &&
		    (*link)->param.id == id) {
			return link;
		}
		link = &(*link)->next;
	}
	return NULL;
}

/*
 * Find a SP and return a pointer to the linked list link to it (i.e. ptr
 * to either the list head or the next field of the previous sp in the list).
 */
static struct ofp_ipsec_sp **ofp_ipsec_find_sp(uint16_t vrf, uint32_t id)
{
	struct ofp_ipsec_sp **link;

	link = ofp_ipsec_find_in_list(&shm->outbound_sp_list, vrf, id);
	if (!link)
		link = ofp_ipsec_find_in_list(&shm->inbound_sp_list, vrf, id);
	return link;
}

/*
 * Insert SP to the right place in the given list according to the priority.
 */
static void ofp_ipsec_sp_insert(struct ofp_ipsec_sp **link,
				struct ofp_ipsec_sp *sp)
{
	while (*link) {
		if ((*link)->param.priority >= sp->param.priority)
			break;
		link = &(*link)->next;
	}
	sp->next = *link;
	*link = sp;
}

int ofp_ipsec_sp_create(const ofp_ipsec_sp_param *param)
{
	struct ofp_ipsec_sp *sp;
	int ret = 0;

	odp_rwlock_write_lock(&shm->lock);

	if (ofp_ipsec_find_sp(param->vrf, param->id)) {
		ret = -1;
		goto fail;
	}
	sp = ofp_ipsec_sp_alloc();
	if (!sp) {
		ret = -1;
		goto fail;
	}
	if (param->direction == OFP_IPSEC_INBOUND)
		ofp_ipsec_sp_insert(&shm->inbound_sp_list, sp);
	else
		ofp_ipsec_sp_insert(&shm->outbound_sp_list, sp);
fail:
	odp_rwlock_write_unlock(&shm->lock);
	return ret;
}

int ofp_ipsec_sp_destroy(uint16_t vrf, uint32_t id)
{
	struct ofp_ipsec_sp **link;
	struct ofp_ipsec_sp *sp;
	int found = 0;

	odp_rwlock_write_lock(&shm->lock);

	link = ofp_ipsec_find_sp(vrf, id);
	if (link) {
		found = 1;
		sp = *link;
		*link = sp->next;
		ofp_ipsec_sp_free(sp);
	}

	odp_rwlock_write_unlock(&shm->lock);
	return !found;
}

int ofp_ipsec_sp_set_sa(uint16_t vrf, uint32_t id, ofp_ipsec_sa_handle sa)
{
	struct ofp_ipsec_sp **link;
	int ret = -1;

	odp_rwlock_write_lock(&shm->lock);

	link = ofp_ipsec_find_sp(vrf, id);
	if (link) {
		ofp_ipsec_sa_handle old_sa = (*link)->sa;
		if (old_sa != OFP_IPSEC_SA_INVALID)
			ofp_ipsec_sa_unref(old_sa);
		if (sa != OFP_IPSEC_SA_INVALID)
			ofp_ipsec_sa_ref(sa);
		(*link)->sa = sa;
		ret = 0;
	}

	odp_rwlock_write_unlock(&shm->lock);
	return ret;
}

static void ofp_ipsec_get_selector_values(odp_packet_t pkt,
					  struct ofp_ipsec_selector_values *s)
{
	struct ofp_ip *ip;
	uint32_t len;

	ip = odp_packet_l3_ptr(pkt, &len);
	if (!ip || len < sizeof(*ip)) {
		memset(s, 0, sizeof(*s));
		return;
	}
	s->src_addr = odp_be_to_cpu_32(ip->ip_src.s_addr);
	s->dst_addr = odp_be_to_cpu_32(ip->ip_dst.s_addr);
	s->ip_proto = ip->ip_p;
}

static int ofp_ipsec_sp_match(const struct ofp_ipsec_sp *sp,
			      const struct ofp_ipsec_selector_values *sel)
{
	if (sel->dst_addr < sp->param.selectors.dst_addr.begin ||
	    sel->dst_addr > sp->param.selectors.dst_addr.end)
		return 0;
	if (sel->ip_proto < sp->param.selectors.proto.begin ||
	    sel->ip_proto > sp->param.selectors.proto.end)
		return 0;
	return -1;
}

static inline ofp_ipsec_sp_action ofp_ipsec_sp_lookup(struct ofp_ipsec_sp *sp,
						      uint16_t vrf,
						      odp_packet_t pkt,
						      ofp_ipsec_sa_handle *sa)
{
	ofp_ipsec_sp_action action;
	struct ofp_ipsec_selector_values sel;

	ofp_ipsec_get_selector_values(pkt, &sel);

	odp_rwlock_read_lock(&shm->lock);
	while (sp) {
		if (sp->param.vrf == vrf && ofp_ipsec_sp_match(sp, &sel))
			break;
		sp = sp->next;
	}
	if (sp)  {
		if (sa) {
			*sa = sp->sa;
			ofp_ipsec_sa_ref(*sa);
		}
		action = sp->param.action;
	} else {
		action = OFP_IPSEC_ACTION_BYPASS;
	}
	odp_rwlock_read_unlock(&shm->lock);

	return action;
}
ofp_ipsec_sp_action ofp_ipsec_sp_out_lookup(uint16_t vrf, odp_packet_t pkt,
					    ofp_ipsec_sa_handle *sa)
{
	return ofp_ipsec_sp_lookup(shm->outbound_sp_list, vrf, pkt, sa);
}

ofp_ipsec_sp_action ofp_ipsec_sp_in_lookup(uint16_t vrf, odp_packet_t pkt)
{
	return ofp_ipsec_sp_lookup(shm->inbound_sp_list, vrf, pkt, NULL);
}
