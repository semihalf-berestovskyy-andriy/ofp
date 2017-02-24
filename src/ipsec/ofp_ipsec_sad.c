/*
 * Copyright (c) 2017, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include "api/ofp_types.h"
#include "api/ofp_log.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_shared_mem.h"
#include "ofpi_ipsec_sad.h"

#define OFP_IPSEC_MAX_SA 100

struct ofp_ipsec_sad {
	odp_rwlock_t lock;
	odp_queue_t compl_queue;
	uint32_t inbound_sa_list;
	uint32_t outbound_sa_list;
	odp_spinlock_t freelist_lock;
	uint32_t free_sa_list;
};

struct ofp_ipsec_sa {
	odp_ipsec_sa_t odp_sa;
	odp_atomic_u32_t refcount;
	uint32_t idx;                /* idx of this SA */
	uint32_t next;               /* idx of the next SA in a linked list */
	ofp_ipsec_sa_param sa_param;
};

#define SHM_NAME_IPSEC_SAD "ofp_ipsec_sad"
static __thread struct ofp_ipsec_sad *shm;

#define SHM_NAME_IPSEC_SA_TABLE "ofp_ipsec_sa_table"
static __thread struct ofp_ipsec_sa *shm_sa_table;

static struct ofp_ipsec_sa *ofp_ipsec_sa_find_by_id(uint32_t list_head,
						    uint16_t vrf,
						    uint32_t id);

static int ofp_ipsec_sa_init(struct ofp_ipsec_sa *sa,
			     const ofp_ipsec_sa_param *param);

static struct ofp_ipsec_sa* ofp_ipsec_sa_in_lookup_unsafe(uint16_t vrf,
							  uint32_t spi);


static inline struct ofp_ipsec_sa *ofp_ipsec_sa_by_idx(uint32_t idx)
{
	return &shm_sa_table[idx];
}

static inline uint32_t ofp_ipsec_sa_idx(struct ofp_ipsec_sa *sa)
{
	return sa->idx;
}

int ofp_ipsec_sad_init_global(uint32_t max_num_sa, odp_queue_t compl_queue)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_IPSEC_SAD, sizeof(*shm));
	if (!shm) {
		OFP_ERR("Failed to allocate IPsec SAD shared memory");
		return -1;
	}
	memset(shm, 0, sizeof(*shm));
	shm->compl_queue = compl_queue;
	odp_rwlock_init(&shm->lock);

	shm->inbound_sa_list = 0;
	shm->outbound_sa_list = 0;
	odp_spinlock_init(&shm->freelist_lock);
	shm->free_sa_list = 0;

	uint64_t sa_table_size = sizeof(*shm_sa_table) * max_num_sa;
	shm_sa_table = ofp_shared_memory_alloc(SHM_NAME_IPSEC_SA_TABLE,
					       sa_table_size);
	if (!shm_sa_table) {
		OFP_ERR("shared memory allocation for SAD failed");
		return -1;
	}

	/* Skip SA #0 since index 0 is our list end marker */
	for (uint32_t n = 1; n < OFP_IPSEC_MAX_SA; n++)
	{
		struct ofp_ipsec_sa *sa = &shm_sa_table[n];
		sa->next = shm->free_sa_list;
		sa->idx = n;
		shm->free_sa_list = n;
	}
	return 0;
}

int ofp_ipsec_sad_term_global(void)
{
	/*
	 * TODO: Implement proper termination
	 * - Flush SAD
	 * - Wait until ODP drains from IPsec ops and SAs get freed
	 * - Free SHMs
	 */
	return -1;
}

static struct ofp_ipsec_sa *ofp_ipsec_sa_alloc(void)
{
	struct ofp_ipsec_sa *sa = NULL;

	odp_spinlock_lock(&shm->freelist_lock);
	if (shm->free_sa_list) {
		sa = ofp_ipsec_sa_by_idx(shm->free_sa_list);
		shm->free_sa_list = sa->next;
	}
	odp_spinlock_unlock(&shm->freelist_lock);
	return sa;
}

static void ofp_ipsec_sa_free(struct ofp_ipsec_sa *sa)
{
	odp_spinlock_lock(&shm->freelist_lock);
	sa->next = shm->free_sa_list;
	shm->free_sa_list = sa->idx;
	odp_spinlock_unlock(&shm->freelist_lock);
}

static odp_ipsec_sa_t ofp_ipsec_odp_sa_create(const struct ofp_ipsec_sa *sa)
{
	odp_ipsec_sa_param_t odp_param;
	odp_u32be_t tun_src = odp_cpu_to_be_32(sa->sa_param.tun_src);
	odp_u32be_t tun_dst = odp_cpu_to_be_32(sa->sa_param.tun_dst);

	odp_ipsec_crypto_param_t crypto = {
		.cipher_alg = ODP_CIPHER_ALG_NULL,
		.cipher_key.data = NULL,
		.cipher_key.length = 0,
		.auth_alg = ODP_AUTH_ALG_MD5_HMAC,
		.auth_key.data = (uint8_t *)"1234567890123456",
		.auth_key.length = 16
	};
	odp_ipsec_tunnel_param_t tunnel = {
		.type = ODP_IPSEC_TUNNEL_IPV4,
		.ipv4.src_addr = &tun_src,
		.ipv4.dst_addr = &tun_dst,
		.ipv4.dscp = 0,
		.ipv4.df = 0,
		.ipv4.ttl = UINT8_MAX
	};
	odp_ipsec_sa_opt_t opt = {
		.esn = 0,
		.udp_encap = 0,
		.copy_dscp = 0,
		.copy_flabel = 0,
		.copy_df = 0,
		.dec_ttl = 0
	};
	odp_ipsec_lifetime_t lifetime = {
		.soft_limit.sec = 0,
		.soft_limit.bytes = 0,
		.soft_limit.packets = 0,
		.hard_limit.sec = 0,
		.hard_limit.bytes = 0,
		.hard_limit.packets = 0
	};

	odp_ipsec_sa_param_init(&odp_param);

	odp_param.dir = sa->sa_param.direction == OFP_IPSEC_INBOUND ?
		ODP_IPSEC_DIR_INBOUND :
		ODP_IPSEC_DIR_OUTBOUND;
	odp_param.proto = ODP_IPSEC_ESP;
	odp_param.mode = sa->sa_param.mode == OFP_IPSEC_TRANSPORT ?
		ODP_IPSEC_MODE_TRANSPORT :
		ODP_IPSEC_MODE_TUNNEL;
	odp_param.crypto = crypto;
	odp_param.tunnel = tunnel;
	odp_param.frag_mode = ODP_IPSEC_FRAG_DISABLED;
	odp_param.opt = opt;
	odp_param.lifetime = lifetime;
	odp_param.lookup_mode = ODP_IPSEC_LOOKUP_DISABLED;
	odp_param.antireplay_ws = 0;
	odp_param.seq = 0;
	odp_param.spi = sa->sa_param.spi;
	odp_param.mtu = UINT32_MAX;
	odp_param.dest_queue = shm->compl_queue;
	odp_param.context = sa; /* now unused, stored in pkt user area too */
	odp_param.context_len = 0;

	return odp_ipsec_sa_create(&odp_param);
}

static int ofp_ipsec_sa_init(struct ofp_ipsec_sa *sa,
			     const ofp_ipsec_sa_param *param)
{
	sa->odp_sa = ofp_ipsec_odp_sa_create(sa);
	if (sa->odp_sa == ODP_IPSEC_SA_INVALID)
		return -1;

	sa->sa_param = *param;
	odp_atomic_store_u32(&sa->refcount, 1);

	odp_rwlock_write_lock(&shm->lock);

	if (ofp_ipsec_sa_find_by_id(shm->inbound_sa_list,
				    param->vrf, param->id) ||
	    ofp_ipsec_sa_find_by_id(shm->outbound_sa_list,
				    param->vrf, param->id)) {

		odp_ipsec_sa_destroy(sa->odp_sa);
		odp_rwlock_write_unlock(&shm->lock);
		return -1;
	}
	if (param->direction == OFP_IPSEC_INBOUND) {
		if (ofp_ipsec_sa_in_lookup_unsafe(param->vrf, param->spi)) {
			odp_ipsec_sa_destroy(sa->odp_sa);
			odp_rwlock_write_unlock(&shm->lock);
			return -1;
		}
		sa->next = shm->inbound_sa_list;
		shm->inbound_sa_list = sa->idx;
	} else {
		sa->next = shm->outbound_sa_list;
		shm->outbound_sa_list = sa->idx;
	}

	odp_rwlock_write_unlock(&shm->lock);
	return 0;
}

struct ofp_ipsec_sa *ofp_ipsec_sa_create(const ofp_ipsec_sa_param *param)
{
	struct ofp_ipsec_sa *sa = ofp_ipsec_sa_alloc();
	if (!sa)
		return OFP_IPSEC_SA_INVALID;

	if (ofp_ipsec_sa_init(sa, param)) {
		ofp_ipsec_sa_free(sa);
		return OFP_IPSEC_SA_INVALID;
	}
	return sa;
}

void ofp_ipsec_sa_destroy(struct ofp_ipsec_sa *sa)
{
	uint32_t *link;
	int found = 0;

	if (sa->sa_param.direction == OFP_IPSEC_INBOUND)
		link = &shm->inbound_sa_list;
	else
		link = &shm->outbound_sa_list;

	odp_rwlock_write_lock(&shm->lock);
	while (*link) {
		struct ofp_ipsec_sa *s = ofp_ipsec_sa_by_idx(*link);
		if (s == sa) {
			*link = s->next;
			found = -1;
			break;
		}
		link = &s->next;
	}
	odp_rwlock_write_unlock(&shm->lock);
	if (found)
		ofp_ipsec_sa_unref(sa);
	/* TODO: error if not found */
}

void ofp_ipsec_sa_iterate(ofp_ipsec_sa_cb cb, void *ctx)
{
	uint32_t idx;
	struct ofp_ipsec_sa *sa;

	odp_rwlock_read_lock(&shm->lock);

	idx = shm->inbound_sa_list;
	while (idx) {
		sa = ofp_ipsec_sa_by_idx(idx);
		if ((*cb)(sa, ctx))
			goto done;
		idx = sa->next;
	}

	idx = shm->outbound_sa_list;
	while (idx) {
		sa = ofp_ipsec_sa_by_idx(idx);
		if ((*cb)(sa, ctx))
			goto done;
		idx = sa->next;
	}

done:
	odp_rwlock_read_unlock(&shm->lock);
}

static struct ofp_ipsec_sa* ofp_ipsec_sa_in_lookup_unsafe(uint16_t vrf,
							  uint32_t spi)
{
	struct ofp_ipsec_sa *sa, *found = NULL;
	uint32_t idx;

	idx = shm->inbound_sa_list;
	while (idx) {
		sa = ofp_ipsec_sa_by_idx(idx);
		if (sa->sa_param.vrf == vrf && sa->sa_param.spi == spi) {
			found = sa;
			break;
		}
		idx = sa->next;
	}
	return found;
}

struct ofp_ipsec_sa *ofp_ipsec_sa_in_lookup(uint16_t vrf, uint32_t spi)
{
	struct ofp_ipsec_sa *sa;

	odp_rwlock_read_lock(&shm->lock);
	sa = ofp_ipsec_sa_in_lookup_unsafe(vrf, spi);
	if (sa)
		ofp_ipsec_sa_ref(sa);
	odp_rwlock_read_unlock(&shm->lock);
	return sa;
}

static struct ofp_ipsec_sa *ofp_ipsec_sa_find_by_id(uint32_t list_head,
						    uint16_t vrf,
						    uint32_t id)
{
	uint32_t idx = list_head;
	struct ofp_ipsec_sa *sa;
	struct ofp_ipsec_sa *found = NULL;

	while (idx) {
		sa = ofp_ipsec_sa_by_idx(idx);
		if (sa->sa_param.vrf == vrf && sa->sa_param.id == id) {
			found = sa;
			break;
		}
		idx = sa->next;
	}
	return found;
}

struct ofp_ipsec_sa *ofp_ipsec_sa_lookup_by_id(uint16_t vrf, uint32_t id)
{
	struct ofp_ipsec_sa *sa = NULL;

	odp_rwlock_read_lock(&shm->lock);
	sa = ofp_ipsec_sa_find_by_id(shm->inbound_sa_list, vrf, id);
	if (!sa)
		ofp_ipsec_sa_find_by_id(shm->outbound_sa_list, vrf, id);
	ofp_ipsec_sa_ref(sa);
	odp_rwlock_read_unlock(&shm->lock);
	return sa;
}

void ofp_ipsec_sa_ref(struct ofp_ipsec_sa *sa)
{
	uint32_t old_val, new_val;

	if (sa == OFP_IPSEC_SA_INVALID)
		return;

	old_val = odp_atomic_load_u32(&sa->refcount);
	do {
		new_val = old_val + 1;
	} while (odp_atomic_cas_acq_rel_u32(&sa->refcount, &old_val, new_val));
}

void ofp_ipsec_sa_unref(struct ofp_ipsec_sa *sa)
{
	uint32_t old_val, new_val;

	if (sa == OFP_IPSEC_SA_INVALID)
		return;

	old_val = odp_atomic_load_u32(&sa->refcount);
	do {
		new_val = old_val - 1;
	} while (odp_atomic_cas_acq_rel_u32(&sa->refcount, &old_val, new_val));

	if (odp_unlikely(old_val == 1)) {
		/* TODO: maybe do not do synchronously in this thread */
		if (odp_ipsec_sa_destroy(sa->odp_sa)) {
			OFP_ERR("Failed to destroy ODP SA");
		}
		ofp_ipsec_sa_free(sa);
	}
}

odp_ipsec_sa_t ofp_ipsec_sa_get_odp_sa(struct ofp_ipsec_sa *sa)
{
	return sa->odp_sa;
}

const ofp_ipsec_sa_param *ofp_ipsec_sa_get_param(struct ofp_ipsec_sa *sa)
{
	return &sa->sa_param;
}
