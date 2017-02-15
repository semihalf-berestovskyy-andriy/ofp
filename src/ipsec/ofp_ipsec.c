/*
 * Copyright (c) 2017, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <inttypes.h>
#include <odp.h>
#include "api/ofp_types.h"
#include "api/ofp_ip6.h"
#include "api/ofp_log.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "api/ofp_ipsec.h"
#include "api/ofp_ipsec_spd.h"
#include "api/ofp_ipsec_sad.h"

/*
 * IPsec async processing context stored in the user area of packets
 */
typedef struct {
	ofp_ipsec_sa_handle sa;
	int is_outbound : 1;
	int is_tunnel : 1;
} ofp_ipsec_op_ctx;

typedef struct {
	union {
		uint8_t flags;
		ofp_ipsec_op_ctx op_ctx;
	};
} ofp_ipsec_pkt_metadata;

static enum ofp_return_code ofp_ipsec_encaps(uint16_t vrf,
					     odp_packet_t pkt,
					     ofp_ipsec_sa_handle sa);

static enum ofp_return_code ofp_ipsec_encaps_continue(odp_packet_t pkt,
						      ofp_ipsec_op_ctx *ctx);

static enum ofp_return_code ofp_ipsec_decaps(uint16_t vrf,
					     odp_packet_t pkt,
					     ofp_ipsec_sa_handle sa);

static enum ofp_return_code ofp_ipsec_decaps_continue(odp_packet_t pkt,
						      ofp_ipsec_op_ctx *ctx);

static enum ofp_return_code ofp_ipsec_result_packet(odp_packet_t pkt,
						    odp_ipsec_packet_result_t *res,
						    int last);


void ofp_ipsec_flags_set(odp_packet_t pkt, uint8_t flags)
{
	/* TODO: Create common OFP pkt metadata */
	ofp_ipsec_pkt_metadata *m = odp_packet_user_area(pkt);
	if (m)
		m->flags = flags;
}

uint8_t ofp_ipsec_flags(const odp_packet_t pkt)
{
	ofp_ipsec_pkt_metadata *m = odp_packet_user_area(pkt);
	return m ? m->flags : 0;
}

int ofp_ipsec_init_global(uint32_t max_num_sa, odp_queue_t compl_queue)
{
	odp_ipsec_config_t config;
	odp_ipsec_capability_t capa;
	odp_queue_param_t queue_param;
	int queue_created = 0;

	if (odp_ipsec_capability(&capa)) {
		OFP_ERR("odp_ipsec_capability failed");
		return -1;
	}
	if (!capa.op_mode_async) {
		OFP_ERR("odp_ipsec_capability: no async capability");
		return -1;
	}
	if (capa.max_num_sa < max_num_sa) {
		OFP_ERR("odp_ipsec_capability: not enough SAs supported "
			"(%" PRIu32 " requested, %" PRIu32 " supported)",
			max_num_sa, capa.max_num_sa);
		return -1;
	}
	odp_ipsec_config_init(&config);
	config.op_mode = ODP_IPSEC_OP_MODE_ASYNC;
	if (odp_ipsec_config(&config)) {
		OFP_ERR("odp_ipsec_config failed");
		return -1;
	}
	if (compl_queue == ODP_QUEUE_INVALID) {
		odp_queue_param_init(&queue_param);
		queue_param.type = ODP_QUEUE_TYPE_SCHED;
		queue_param.enq_mode = ODP_QUEUE_OP_MT;
		queue_param.deq_mode = ODP_QUEUE_OP_DISABLED;
		queue_param.sched.sync = ODP_SCHED_SYNC_ORDERED;
		compl_queue = odp_queue_create("IPsec completion",
					       &queue_param);
		if (compl_queue == ODP_QUEUE_INVALID) {
			OFP_ERR("failed to create IPsec completion queue");
			return -1;
		}
		queue_created = 1;
	}
	if (ofp_ipsec_sad_init_global(max_num_sa, compl_queue)) {
		if (queue_created)
			(void) odp_queue_destroy(compl_queue);
		return -1;
	}
	if (ofp_ipsec_spd_init_global()) {
		if (queue_created)
			(void) odp_queue_destroy(compl_queue);
		(void) ofp_ipsec_sad_term_global();
		return -1;
	}
	return 0;
}

static enum ofp_return_code ofp_ipsec_sa_acquire(uint16_t vrf,
						 odp_packet_t pkt)
{
	(void) vrf;
	(void) pkt;
	/*
	 * TODO: - Callback to application code.
	 *       - Maybe provide policy info too.
	 *       - Buffer packet
	 */
	return OFP_PKT_DROP;
}

enum ofp_return_code ofp_ipsec_output(uint16_t vrf,
				      odp_packet_t pkt)
{
	ofp_ipsec_sp_action action;
	ofp_ipsec_sa_handle sa;

	if (ofp_ipsec_flags(pkt) & OFP_IPSEC_OUTBOUND_DONE)
		return OFP_PKT_CONTINUE;

	action = ofp_ipsec_sp_out_lookup(vrf, pkt, &sa);
	switch (action) {
	case OFP_IPSEC_ACTION_BYPASS:
		return OFP_PKT_CONTINUE;
	case OFP_IPSEC_ACTION_IPSEC:
		if (odp_unlikely(sa == OFP_IPSEC_SA_INVALID)) {
			return ofp_ipsec_sa_acquire(vrf, pkt);
		} else
			return ofp_ipsec_encaps(vrf, pkt, sa);
	case OFP_IPSEC_ACTION_DISCARD:
	default:
		break;
	}
	return OFP_PKT_DROP;
}

enum ofp_return_code ofp_esp4_input(odp_packet_t pkt, int off)
{
	struct ofp_ifnet *dev;
	int vrf;
	uint32_t spi;
	struct ofp_ip *ip;
	ofp_ipsec_sa_handle sa;

	dev = odp_packet_user_ptr(pkt);
	vrf = dev->vrf;

	/* TODO: Buffer length check needed? */
	ip = (struct ofp_ip *) odp_packet_l3_ptr(pkt, NULL);
	spi = *(uint32_t*) ((uint8_t *) ip + off);

	sa = ofp_ipsec_sa_in_lookup(vrf, spi);
	if (!sa) {
		return OFP_PKT_DROP;
	}

	return ofp_ipsec_decaps(vrf, pkt, sa);
}

enum ofp_return_code ofp_ah4_input(odp_packet_t pkt, int off)
{
	return ofp_esp4_input(pkt, off);
}

static enum ofp_return_code ofp_ipsec_decaps(uint16_t vrf,
					     odp_packet_t pkt,
					     ofp_ipsec_sa_handle sa)
{
	odp_ipsec_op_param_t param = {0};
	const ofp_ipsec_sa_param *sa_param = ofp_ipsec_sa_get_param(sa);
	odp_ipsec_sa_t odp_sa = ofp_ipsec_sa_get_odp_sa(sa);
	ofp_ipsec_pkt_metadata *m = odp_packet_user_area(pkt);
	int ret;

	(void) vrf;

	if (odp_unlikely(!m)) {
		ofp_ipsec_sa_unref(sa);
		return OFP_PKT_DROP;
	}

	m->op_ctx.sa = sa;
	m->op_ctx.is_outbound = 0;
	m->op_ctx.is_tunnel = (sa_param->mode == OFP_IPSEC_TUNNEL);

	param.num_pkt = 1;
	param.num_sa = 1;
	param.num_opt = 0;
	param.pkt = &pkt;
	param.sa = &odp_sa;
	ret = odp_ipsec_in_enq(&param);
	if (odp_unlikely(ret < 0)) {
		OFP_ERR("odp_ipsec_in_enq() failed: %d", ret);
		ofp_ipsec_sa_unref(sa);
		return OFP_PKT_DROP;
	}
	return OFP_PKT_ON_HOLD;
}

/*
 * Continue IPsec decapsulation after ODP IPsec processing
 */
static enum ofp_return_code ofp_ipsec_decaps_continue(odp_packet_t pkt,
						      ofp_ipsec_op_ctx *ctx)
{
	/* TODO: Do tunnel exit policy check */

	ofp_ipsec_flags_set(pkt, OFP_IPSEC_INBOUND_DONE);

	if (!ctx->is_tunnel) {
		if (odp_packet_has_ipv4(pkt)) {
			struct ofp_ip *ip;
			/* TODO: Buffer lenght check needed? */
			ip = (struct ofp_ip *) odp_packet_l3_ptr(pkt, NULL);
			/* TODO: Call local hook again? */
			return ipv4_transport_classifier(pkt, ip->ip_p);
		} else {
			/* Does not happen yet due to missing IPv6 support */
			struct ofp_ip6_hdr *ipv6;
			ipv6 = (struct ofp_ip6_hdr *) odp_packet_l3_ptr(pkt, NULL);
			/* TODO: Call local hook again? */
			return ipv6_transport_classifier(pkt, ipv6->ofp_ip6_nxt);
		}
	} else {
		if (odp_packet_has_ipv4(pkt)) {
			return ofp_ipv4_processing(pkt);
		} else {
			return ofp_ipv6_processing(pkt);
		}
	}
	/* NOTREACHED */
	return OFP_PKT_DROP;
}

static enum ofp_return_code ofp_ipsec_encaps(uint16_t vrf,
					     odp_packet_t pkt,
					     ofp_ipsec_sa_handle sa)
{
	odp_ipsec_op_param_t param = {0};
	const ofp_ipsec_sa_param *sa_param = ofp_ipsec_sa_get_param(sa);
	odp_ipsec_sa_t odp_sa = ofp_ipsec_sa_get_odp_sa(sa);
	ofp_ipsec_pkt_metadata *m = odp_packet_user_area(pkt);
	int ret;

	(void) vrf;

	if (odp_unlikely(!m)) {
		ofp_ipsec_sa_unref(sa);
		return OFP_PKT_DROP;
	}

	m->op_ctx.sa = sa;
	m->op_ctx.is_outbound = 1;
	m->op_ctx.is_tunnel = (sa_param->mode == OFP_IPSEC_TUNNEL); /* now unused */

	if (!m->op_ctx.is_tunnel) {
		/* TODO: check that this is not a forwarded packet */
	}

	param.num_pkt = 1;
	param.num_sa = 1;
	param.pkt = &pkt;
	param.sa = &odp_sa;

	ret = odp_ipsec_out_enq(&param);
	if (odp_unlikely(ret < 0)) {
		ofp_ipsec_sa_unref(sa);
		OFP_ERR("odp_ipsec_out_enq() failed: %d", ret);
		return OFP_PKT_DROP;
	}
	return OFP_PKT_ON_HOLD;
}

/*
 * Continue IPsec encapsulation after ODP IPsec processing
 */
static enum ofp_return_code ofp_ipsec_encaps_continue(odp_packet_t pkt,
						      ofp_ipsec_op_ctx *ctx)
{
	(void) ctx;
	ofp_ipsec_flags_set(pkt, OFP_IPSEC_OUTBOUND_DONE);

	if (odp_packet_has_ipv4(pkt))
		return ofp_ip_output_real(pkt, NULL);
	else
		return ofp_ip6_output(pkt, NULL); /* TODO: fix IPv6 support */
}

void ofp_ipsec_result(odp_event_t ev)
{
	static __thread int num = 0;
	static __thread odp_packet_t *pkt = NULL;
	static __thread odp_ipsec_packet_result_t *pktr = NULL;

	odp_ipsec_op_result_t res;
	int n = num + 1;

	while (n > num) {
		num = n;
		pkt = realloc(pkt, sizeof(pkt)*num);
		pktr = realloc(pktr, sizeof(pktr)*num);
		res.num_pkt = num;
		res.pkt = pkt;
		res.res = pktr;

		n = odp_ipsec_result(&res, ev);

		if (n < 0) {
			OFP_ERR("odp_ipsec_result() error.\n");
			return;
		}
	}
	odp_event_free(ev);

	for (int i = 0; i < res.num_pkt; i++) {
		int last;

		if (i == res.num_pkt - 1 || res.res[i+1].num_out != 0)
			/*
			 * We assume that all fragments resulting from
			 * the same IPsec operation are returned in
			 * the same event.
			 *
			 * TODO: Is it a valid assumption? If not
			 * get a nicer ODP API or do SA refcount
			 * incr + decr dance here.
			 */
			last = 1;
		else
			last = 0;
		if (ofp_ipsec_result_packet(res.pkt[i], &res.res[i], last)
		    == OFP_PKT_DROP) {
			odp_packet_free(res.pkt[i]);
		}
	}
}

static ofp_ipsec_cb ofp_ipsec_sa_soft_expiry = {NULL, NULL};
static ofp_ipsec_cb ofp_ipsec_sa_hard_expiry = {NULL, NULL};

void ofp_ipsec_register_callbacks(ofp_ipsec_cb sa_soft_expiry,
				  ofp_ipsec_cb sa_hard_expiry)
{
	ofp_ipsec_sa_soft_expiry = sa_soft_expiry;
	ofp_ipsec_sa_hard_expiry = sa_hard_expiry;
}

static enum ofp_return_code ofp_ipsec_result_packet(odp_packet_t pkt,
						    odp_ipsec_packet_result_t *res,
						    int last)
{
	ofp_ipsec_pkt_metadata *m = odp_packet_user_area(pkt);
	int mtu = 0;
	enum ofp_return_code ret = OFP_PKT_CONTINUE;
	odp_ipsec_status_t status = res->status;
	ofp_ipsec_op_ctx *ctx = NULL;

	if (m)
		ctx = &m->op_ctx;
	else {
		OFP_ERR("No packet user area in IPsec completion");
		return OFP_PKT_DROP; /* SA leak */
	}

	if (odp_unlikely(status.all)) {
		if (status.error.soft_exp_sec ||
		    status.error.soft_exp_bytes ||
		    status.error.soft_exp_packets) {
			ofp_ipsec_cb *cb = &ofp_ipsec_sa_soft_expiry;
			if (cb->func != NULL)
				ret = cb->func(pkt, ctx->sa, cb->ctx);
			status.error.soft_exp_sec = 0;
			status.error.soft_exp_bytes = 0;
			status.error.soft_exp_packets = 0;
		}
		if (status.error.proto ||
		    status.error.alg ||
		    status.error.sa_lookup ||
		    status.error.antireplay ||
		    status.error.auth) {
			ret = OFP_PKT_DROP;
		}
		if (status.error.hard_exp_sec ||
		    status.error.hard_exp_bytes ||
		    status.error.hard_exp_packets) {
			ofp_ipsec_cb *cb = &ofp_ipsec_sa_hard_expiry;
			if (cb->func != NULL)
				ret = cb->func(pkt, ctx->sa, cb->ctx);
			else
				ret = OFP_PKT_DROP;
			status.error.hard_exp_sec = 0;
			status.error.hard_exp_bytes = 0;
			status.error.hard_exp_packets = 0;
		}

		if (status.error.mtu) {
			status.error.mtu = 0;
			mtu = 1;
		}
		if (status.all) {
			OFP_ERR("Unknown IPsec processing error");
			ret = OFP_PKT_DROP;
		}

		if (mtu) {
			/* Now unused */
			/* TODO: Do red-side fragmentation or PMTUD action */
			ret = OFP_PKT_DROP;
		}
	}

	if (ret == OFP_PKT_CONTINUE) {
		if (ctx->is_outbound)
			ret = ofp_ipsec_encaps_continue(pkt, ctx);
		else
			ret = ofp_ipsec_decaps_continue(pkt, ctx);
	}
	if (last) {
		/*
		 * Unreference the SA only once for a set of output
		 * packets that result from single input packet.
		 */
		ofp_ipsec_sa_unref(ctx->sa);
	}
	return ret;
}
