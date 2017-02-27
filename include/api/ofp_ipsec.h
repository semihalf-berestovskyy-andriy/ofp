/*
 * Copyright (c) 2017, Cavium
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef OFP_IPSEC_H
#define OFP_IPSEC_H

#include <odp.h>
#include <ofp_in.h>
#include <ofp_in6.h>

/***********************************************************************
 * OFP Security Association Database Structures
 **********************************************************************/

/**
 * IPSEC SA handle
 */
typedef struct ofp_ipsec_sa *ofp_ipsec_sa_handle;
#define OFP_IPSEC_SA_INVALID ((ofp_ipsec_sa_handle)0)

/**
 * IPSEC SA/SP direction
 */
typedef enum ofp_ipsec_dir_t {
	/** Inbound IPSEC SA/SP */
	OFP_IPSEC_DIR_INBOUND = ODP_IPSEC_DIR_INBOUND,
	/** Outbound IPSEC SA/SP */
	OFP_IPSEC_DIR_OUTBOUND = ODP_IPSEC_DIR_OUTBOUND
} ofp_ipsec_dir_t;

/**
 * IPSEC protocol
 */
typedef enum ofp_ipsec_proto_t {
	/** ESP protocol */
	OFP_IPSEC_PROTO_ESP = ODP_IPSEC_PROTO_ESP,
	/** AH protocol */
	OFP_IPSEC_PROTO_AH = ODP_IPSEC_PROTO_AH
} ofp_ipsec_proto_t;

/**
 * IPSEC mode
 */
typedef enum ofp_ipsec_mode_t {
	/** IPSEC tunnel mode */
	OFP_IPSEC_MODE_TUNNEL = ODP_IPSEC_MODE_TUNNEL,
	/** IPSEC transport mode */
	OFP_IPSEC_MODE_TRANSPORT = ODP_IPSEC_MODE_TRANSPORT
} ofp_ipsec_mode_t;

/**
 * IPSEC cipher algorithm
 */
typedef enum ofp_ipsec_cipher_alg_t {
	/** No cipher algorithm specified */
	OFP_IPSEC_CIPHER_ALG_NULL = ODP_CIPHER_ALG_NULL,
	/** DES */
	OFP_IPSEC_CIPHER_ALG_DES = ODP_CIPHER_ALG_DES,
	/** Triple DES with cipher block chaining */
	OFP_IPSEC_CIPHER_ALG_3DES_CBC = ODP_CIPHER_ALG_3DES_CBC,
	/** AES with cipher block chaining */
	OFP_IPSEC_CIPHER_ALG_AES_CBC = ODP_CIPHER_ALG_AES_CBC,
	/** AES in Galois/Counter Mode
	 *
	 *  @note Must be paired with cipher OFP_IPSEC_AUTH_ALG_AES_GCM
	 */
	OFP_IPSEC_CIPHER_ALG_AES_GCM = ODP_CIPHER_ALG_AES_GCM
} ofp_ipsec_cipher_alg_t;

/**
 * IPSEC maximum key size
 */
#define OFP_IPSEC_MAX_KEY_SZ 512

/**
 * IPSEC key structure
 */
typedef struct ofp_ipsec_key_t {
	/** Key length in bytes */
	uint16_t key_len;
	/** Key data */
	uint8_t key_data[OFP_IPSEC_MAX_KEY_SZ];
} ofp_ipsec_key_t;

/**
 * IPSEC authentication algorithm
 */
typedef enum ofp_ipsec_auth_alg_t {
	/** No authentication algorithm specified */
	OFP_IPSEC_AUTH_ALG_NULL = ODP_AUTH_ALG_NULL,
	/** HMAC-MD5
	 *
	 * MD5 algorithm in HMAC mode
	 */
	OFP_IPSEC_AUTH_ALG_MD5_HMAC = ODP_AUTH_ALG_MD5_HMAC,
	/** HMAC-SHA-256
	 *
	 *  SHA-256 algorithm in HMAC mode
	 */
	OFP_IPSEC_AUTH_ALG_SHA256_HMAC = ODP_AUTH_ALG_SHA256_HMAC,
	/** AES in Galois/Counter Mode
	 *
	 *  @note Must be paired with cipher OFP_IPSEC_CIPHER_ALG_AES_GCM
	 */
	OFP_IPSEC_AUTH_ALG_AES_GCM = ODP_AUTH_ALG_AES_GCM
} ofp_ipsec_auth_alg_t;

/**
 * IPSEC crypto parameters
 */
typedef struct ofp_ipsec_crypto_param_t {
	/** Cipher algorithm */
	ofp_ipsec_cipher_alg_t cipher_alg;
	/** Cipher key */
	ofp_ipsec_key_t cipher_key;
	/** Authentication algorithm */
	ofp_ipsec_auth_alg_t auth_alg;
	/** Authentication key */
	ofp_ipsec_key_t auth_key;
} ofp_ipsec_crypto_param_t;

/**
 * IPSEC tunnel type
 */
typedef enum ofp_ipsec_tunnel_type_t {
	/** Outer header is IPv4 */
	OFP_IPSEC_TUNNEL_IPV4 = ODP_IPSEC_TUNNEL_IPV4,
	/** Outer header is IPv6 */
	OFP_IPSEC_TUNNEL_IPV6 = ODP_IPSEC_TUNNEL_IPV6
} ofp_ipsec_tunnel_type_t;

/**
 * IPSEC tunnel parameters
 *
 * These parameters are used to build outbound tunnel headers.
 * All values are passed in CPU native byte / bit order if not
 * specified otherwise. IP addresses must be in NETWORK byte order.
 */
typedef struct ofp_ipsec_tunnel_param_t {
	/** Tunnel type: IPv4 or IPv6 */
	ofp_ipsec_tunnel_type_t type;
	union {
		/** IPv4 header parameters */
		struct {
			/** IPv4 source address (NETWORK ENDIAN) */
			struct ofp_in_addr src_addr;
			/** IPv4 destination address (NETWORK ENDIAN) */
			struct ofp_in_addr dst_addr;
			/** IPv4 Differentiated Services Code Point */
			uint8_t dscp;
			/** IPv4 Time To Live */
			uint8_t ttl;
		} ipv4;
		/** IPv6 header parameters */
		struct {
			/** IPv6 source address (NETWORK ENDIAN) */
			struct ofp_in6_addr src_addr;
			/** IPv6 destination address (NETWORK ENDIAN) */
			struct ofp_in6_addr dst_addr;
			/** IPv6 flow label */
			uint32_t flabel;
			/** IPv6 Differentiated Services Code Point */
			uint8_t dscp;
			/** IPv6 hop limit */
			uint8_t hlimit;
		} ipv6;
	};
} ofp_ipsec_tunnel_param_t;

/**
 * IPSEC SA option flags
 */
typedef struct ofp_ipsec_sa_opt_t {
	/** Extended Sequence Numbers (ESN)
	 *
	 * * 1: Use extended (64 bit) sequence numbers
	 * * 0: Use normal sequence numbers
	 */
	uint32_t esn : 1;
	/** UDP encapsulation
	 *
	 * * 1: Do UDP encapsulation/decapsulation so that IPSEC packets can
	 *      traverse through NAT boxes.
	 * * 0: No UDP encapsulation
	 */
	uint32_t udp_encap : 1;
	/** Copy DSCP bits
	 *
	 * * 1: Copy IPv4 or IPv6 DSCP bits from inner IP header to
	 *      the outer IP header in encapsulation, and vice versa in
	 *      decapsulation.
	 * * 0: Use values from ofp_ipsec_tunnel_param_t in encapsulation and
	 *      do not change DSCP field in decapsulation.
	 */
	uint32_t copy_dscp : 1;
	/** Copy IPv6 Flow Label
	 *
	 * * 1: Copy IPv6 flow label from inner IPv6 header to the
	 *      outer IPv6 header.
	 * * 0: Use value from ofp_ipsec_tunnel_param_t
	 */
	uint32_t copy_flabel : 1;
} ofp_ipsec_sa_opt_t;

/**
 * IPSEC SA/SP lifetime limits
 *
 * These limits are used for setting up SA/SP lifetime. IPSEC operations
 * check against the limits and output a status code when a limit is
 * crossed. Any number of limits may be used simultaneously.
 * Use zero when there is no limit.
 */
typedef odp_ipsec_lifetime_t ofp_ipsec_lifetime_t;

/**
 * IPSEC Security Association (SA) parameters
 */
typedef struct ofp_ipsec_sa_param_t {
	/** IPSEC SA direction: inbound or outbound */
	ofp_ipsec_dir_t dir;
	/** IPSEC protocol: ESP or AH */
	ofp_ipsec_proto_t proto;
	/** IPSEC protocol mode: transport or tunnel */
	ofp_ipsec_mode_t mode;
	/** Parameters for crypto and authentication algorithms */
	ofp_ipsec_crypto_param_t crypto;
	/** Parameters for tunnel mode */
	ofp_ipsec_tunnel_param_t tunnel;
	/** Various SA option flags */
	ofp_ipsec_sa_opt_t opt;
	/** SA lifetime parameters */
	ofp_ipsec_lifetime_t lifetime;
	/** Minimum anti-replay window size. Use 0 to disable anti-replay
	  * service. */
	uint32_t antireplay_ws;
	/** SPI value */
	uint32_t spi;
	/** TODO: compat with existing code */
	uint16_t vrf;
} ofp_ipsec_sa_param_t;

/***********************************************************************
 * OFP Security Association Database API
 **********************************************************************/

/**
 * Initialize IPSEC SA parameters
 *
 * Initialize an ofp_ipsec_sa_param_t to its default values for
 * all fields.
 *
 * @param param		Pointer to the parameter structure
 */
void ofp_ipsec_sa_param_init(ofp_ipsec_sa_param_t *param);

/**
 * Create IPSEC SA
 *
 * Create a new IPSEC SA according to the parameters.
 *
 * @param vrf		VRF to use
 * @param param		IPSEC SA parameters
 *
 * @return IPSEC SA handle
 * @retval OFP_IPSEC_SA_INVALID on failure
 *
 * @see ofp_ipsec_sa_param_init()
 */
ofp_ipsec_sa_handle ofp_ipsec_sa_create(uint16_t vrf,
					const ofp_ipsec_sa_param_t *param);

/**
 * Destroy IPSEC SA
 *
 * Destroy specified IPSEC security association.
 *
 * @param vrf	VRF to use
 * @param sa	IPSEC SA to be destroyed
 *
 * @retval 0	On success
 * @retval <0	On failure
 *
 * @see ofp_ipsec_sa_create()
 */
int ofp_ipsec_sa_destroy(uint16_t vrf, ofp_ipsec_sa_handle sa);

/**
 * Flush IPSEC SAs
 *
 * Flush (destroy all) the IPSEC security associations.
 *
 * @param vrf	VRF to use
 *
 * @retval 0	On success
 * @retval <0	On failure
 *
 * @see ofp_ipsec_sa_destroy()
 */
int ofp_ipsec_sa_flush(uint16_t vrf);

/***********************************************************************
 * OFP Security Policy Database Structures
 **********************************************************************/

/**
 * IPSEC SP handle
 */
typedef struct ofp_ipsec_sp *ofp_ipsec_sp_handle;
#define OFP_IPSEC_SP_INVALID ((ofp_ipsec_sp_handle)0)

/**
 * IPSEC SP actions
 */
typedef enum ofp_ipsec_action_t {
	/** IPSEC DISCARD action */
	OFP_IPSEC_ACTION_DISCARD = 0,
	/** IPSEC BYPASS action*/
	OFP_IPSEC_ACTION_BYPASS,
	/** IPSEC PROTECT action*/
	OFP_IPSEC_ACTION_PROTECT
} ofp_ipsec_action_t;

/**
 * IPSEC SP selector type
 */
typedef enum ofp_ipsec_selector_type_t {
	/** Security policy selector is IPv4 */
	OFP_IPSEC_SELECTOR_IPV4 = 0,
	/** Security policy selector is IPv6 */
	OFP_IPSEC_SELECTOR_IPV6
} ofp_ipsec_selector_type_t;

/**
 * IPSEC selector
 *
 * These selectors are used to match inbound / outbound packets.
 * All values are passed in CPU native byte / bit order if not specified
 * otherwise.
 * IP addresses must be in NETWORK byte order as those are passed in with
 * pointers and copied byte-by-byte from memory to the packet.
 */
typedef struct ofp_ipsec_selector_t {
	/** Selector type: IPv4 or IPv6 */
	ofp_ipsec_selector_type_t type;
	/** TODO: 4 bytes gap */
	/** Source IP address range selector */
	union {
		/** IPv4 selector parameters. Note: for ANY set first = last =
		 * NULL */
		struct {
			/** IPv4 first source address in range (NETWORK ENDIAN)
			 */
			struct ofp_in_addr first_addr;
			/** IPv4 last source address in range (NETWORK ENDIAN)
			 */
			struct ofp_in_addr last_addr;
		} src_ipv4_range;
		/** IPv6 selector parameters. Note: for ANY set first = last =
		 * NULL */
		struct {
			/** IPv6 first source address in range (NETWORK ENDIAN)
			 */
			struct ofp_in6_addr first_addr;
			/** IPv6 last source address in range (NETWORK ENDIAN)
			 */
			struct ofp_in6_addr last_addr;
		} src_ipv6_range;
	};
	/** Destination IP address range selector */
	union {
		/** IPv4 selector parameters. Note: for ANY set first = last =
		 * NULL */
		struct {
			/** IPv4 first destination address in range (NETWORK
			 * END.) */
			struct ofp_in_addr first_addr;
			/** IPv4 last destination address in range (NETWORK
			 * END.) */
			struct ofp_in_addr last_addr;
		} dst_ipv4_range;
		/** IPv6 selector parameters. Note: for ANY set first = last =
		 * NULL */
		struct {
			/** IPv6 first destination address in range (NETWORK
			 * END.) */
			struct ofp_in6_addr first_addr;
			/** IPv6 last destination address in range (NETWORK
			 * END.) */
			struct ofp_in6_addr last_addr;
		} dst_ipv6_range;
	};
	/**
	 * Source port range selector.
	 * for ANY set first = last = 0
	 * for OPAQUE set first > last
	 */
	struct {
		/** First source port in range (NETWORK ENDIAN) */
		uint16_t first_port;
		/** Last source port in range (NETWORK ENDIAN) */
		uint16_t last_port;
	} src_port_range;
	/**
	 * Destination port range selector.
	 * for ANY set first = last = 0
	 * for OPAQUE set first > last
	 */
	struct {
		/** First destination port in range (NETWORK ENDIAN) */
		uint16_t first_port;
		/** Last destination port in range (NETWORK ENDIAN) */
		uint16_t last_port;
	} dst_port_range;
	/**
	 * IP protocol selector.
	 * for ANY set ip_proto = 0
	 * OPAQUE is not supported by StrongSwan
	 */
	uint16_t ip_proto;
	/** TODO: interface? */
} ofp_ipsec_selector_t;

/**
 * IPSEC Security Policy (SP) parameters
 */
typedef struct ofp_ipsec_sp_param_t {
	/** Security Policy priority */
	uint32_t priority;
	/** Security Policy action */
	ofp_ipsec_action_t action;
	/** Security Association Database handle to use */
	ofp_ipsec_sa_handle sa;
	/** SP direction: inbound or outbound */
	ofp_ipsec_dir_t dir;
	/** SP selector */
	ofp_ipsec_selector_t selector;
	/** SP lifetime parameters */
	ofp_ipsec_lifetime_t lifetime;
	/** TODO: compat with existing code */
	uint16_t vrf;
} ofp_ipsec_sp_param_t;

/***********************************************************************
 * OFP Security Policy Database API
 **********************************************************************/

/**
 * Initialize IPSEC SP parameters
 *
 * Initialize an ofp_ipsec_sp_param_t to its default values for all fields.
 *
 * @param param	Pointer to the parameter structure
 */
void ofp_ipsec_sp_param_init(ofp_ipsec_sp_param_t *param);

/**
 * Create IPSEC SP
 *
 * Create a new IPSEC SP according to the parameters.
 *
 * @param vrf	VRF to use
 * @param param	IPSEC SP parameters
 *
 * @return IPSEC SP handle
 * @retval OFP_IPSEC_SP_INVALID on failure
 *
 * @see ofp_ipsec_sp_param_init()
 */
ofp_ipsec_sp_handle ofp_ipsec_sp_create(uint16_t vrf,
					const ofp_ipsec_sp_param_t *param);

/**
 * Bind IPSEC SP to SA
 *
 * Bind a IPSEC SP to the specified SA.
 *
 * @param vrf	VRF to use
 * @param sp	IPSEC SP to bind
 * @param sa	IPSEC SA to bind
 *
 * @retval 0	On success
 * @retval <0	On failure
 *
 * @see ofp_ipsec_sp_create()
 */
ofp_ipsec_sp_handle ofp_ipsec_sp_bind(uint16_t vrf, ofp_ipsec_sp_handle sp,
				      ofp_ipsec_sa_handle sa);

/**
 * Destroy IPSEC SP
 *
 * Destroy specified IPSEC security policy.
 *
 * @param vrf	VRF to use
 * @param sp	IPSEC SP to be destroyed
 *
 * @retval 0	On success
 * @retval <0	On failure
 *
 * @see ofp_ipsec_sp_create()
 */
int ofp_ipsec_sp_destroy(uint16_t vrf, ofp_ipsec_sp_handle sp);

/**
 * Flush IPSEC SPs
 *
 * Flush (destroy all) the IPSEC security policies.
 *
 * @retval 0	On success
 * @retval <0	On failure
 *
 * @param vrf	VRF to use
 *
 * @see ofp_ipsec_sp_destroy()
 */
int ofp_ipsec_sp_flush(uint16_t vrf);

#endif /* OFP_IPSEC_H */
