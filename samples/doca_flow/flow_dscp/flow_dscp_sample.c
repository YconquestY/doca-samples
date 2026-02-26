/*
 * Copyright (c) 2026 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>

#include <doca_log.h>
#include <doca_flow.h>
#include <doca_flow_net.h>

#include <flow_common.h>
#include <flow_switch_common.h>

DOCA_LOG_REGISTER(FLOW_DSCP);

#define FLOW_DSCP_ROOT_NUM_ENTRIES (1)
#define FLOW_DSCP_CLASSIFIER_NUM_ENTRIES (3)
#define FLOW_DSCP_NUM_ENTRIES (FLOW_DSCP_ROOT_NUM_ENTRIES + FLOW_DSCP_CLASSIFIER_NUM_ENTRIES)
#define FLOW_DSCP_NUM_COUNTERS (2)
#define FLOW_DSCP_WAIT_TIME_SEC (20)
#define FLOW_DSCP_ECN_MASK (0xfc)

struct dscp_stats_context {
	uint8_t dscp;
	struct doca_flow_pipe_entry *dscp_entry;
	struct doca_flow_pipe_entry *other_dscp_entry;
};

static doca_error_t create_rocev2_dscp_pipe(struct doca_flow_port *port,
					    struct doca_flow_target *kernel_target,
					    uint8_t dscp,
					    struct entries_status *status,
					    struct doca_flow_pipe **pipe,
					    struct doca_flow_pipe_entry **dscp_entry,
					    struct doca_flow_pipe_entry **other_dscp_entry)
{
	struct doca_flow_pipe_cfg *pipe_cfg = NULL;
	struct doca_flow_fwd fwd;
	struct doca_flow_match match;
	struct doca_flow_match match_mask;
	struct doca_flow_monitor monitor;
	doca_error_t result;

	memset(&fwd, 0, sizeof(fwd));
	memset(&match, 0, sizeof(match));
	memset(&match_mask, 0, sizeof(match_mask));
	memset(&monitor, 0, sizeof(monitor));

	fwd.type = DOCA_FLOW_FWD_TARGET;
	fwd.target = kernel_target;

	result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		return result;
	}

	result = set_flow_pipe_cfg(pipe_cfg, "ROCEV2_DSCP_PIPE", DOCA_FLOW_PIPE_CONTROL, false);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to configure pipe: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, FLOW_DSCP_CLASSIFIER_NUM_ENTRIES);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set number of entries: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set pipe domain: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_create(pipe_cfg, NULL, NULL, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create RoCEv2 DSCP pipe: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	doca_flow_pipe_cfg_destroy(pipe_cfg);
	pipe_cfg = NULL;

	/* Highest priority: RoCEv2 traffic with the requested DSCP value. */
	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
	match.outer.ip4.next_proto = DOCA_FLOW_PROTO_UDP;
	match.outer.roce_v2.udp.l4_port.dst_port = DOCA_HTOBE16(DOCA_FLOW_ROCEV2_DEFAULT_PORT);
	match.outer.ip4.dscp_ecn = (uint8_t)(dscp << 2);

	match_mask.outer.l3_type = UINT32_MAX;
	match_mask.outer.l4_type_ext = UINT32_MAX;
	match_mask.outer.ip4.next_proto = UINT8_MAX;
	match_mask.outer.roce_v2.udp.l4_port.dst_port = UINT16_MAX;
	match_mask.outer.ip4.dscp_ecn = FLOW_DSCP_ECN_MASK;

	monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	result = doca_flow_pipe_control_add_entry(0,
						  0,
						  *pipe,
						  &match,
						  &match_mask,
						  NULL,
						  NULL,
						  NULL,
						  NULL,
						  &monitor,
						  &fwd,
						  status,
						  dscp_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add DSCP-matching entry: %s", doca_error_get_descr(result));
		doca_flow_pipe_destroy(*pipe);
		*pipe = NULL;
		return result;
	}

	/* Next priority: RoCEv2 traffic with any other DSCP value. */
	memset(&match, 0, sizeof(match));
	memset(&match_mask, 0, sizeof(match_mask));
	memset(&monitor, 0, sizeof(monitor));
	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
	match.outer.ip4.next_proto = DOCA_FLOW_PROTO_UDP;
	match.outer.roce_v2.udp.l4_port.dst_port = DOCA_HTOBE16(DOCA_FLOW_ROCEV2_DEFAULT_PORT);

	/* Keep entry as RoCEv2-only while leaving DSCP value as don't-care. */
	match_mask.outer.l3_type = UINT32_MAX;
	match_mask.outer.l4_type_ext = UINT32_MAX;
	match_mask.outer.ip4.next_proto = UINT8_MAX;
	match_mask.outer.roce_v2.udp.l4_port.dst_port = UINT16_MAX;
	match_mask.outer.ip4.dscp_ecn = 0;

	monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	result = doca_flow_pipe_control_add_entry(0,
						  1,
						  *pipe,
						  &match,
						  &match_mask,
						  NULL,
						  NULL,
						  NULL,
						  NULL,
						  &monitor,
						  &fwd,
						  status,
						  other_dscp_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add non-DSCP entry: %s", doca_error_get_descr(result));
		doca_flow_pipe_destroy(*pipe);
		*pipe = NULL;
		return result;
	}

	/* Lowest priority catch-all to preserve non-RoCE traffic routed from root pipe. */
	memset(&match, 0, sizeof(match));
	result = doca_flow_pipe_control_add_entry(0,
						  2,
						  *pipe,
						  &match,
						  NULL,
						  NULL,
						  NULL,
						  NULL,
						  NULL,
						  NULL,
						  &fwd,
						  status,
						  NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add DSCP classifier catch-all entry: %s", doca_error_get_descr(result));
		doca_flow_pipe_destroy(*pipe);
		*pipe = NULL;
		return result;
	}

	return DOCA_SUCCESS;

destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

static doca_error_t create_root_rocev2_pipe(struct doca_flow_port *port,
					    struct doca_flow_pipe *next_pipe,
					    struct entries_status *status,
					    struct doca_flow_pipe **pipe)
{
	struct doca_flow_pipe_cfg *pipe_cfg = NULL;
	struct doca_flow_fwd fwd;
	struct doca_flow_match match;
	doca_error_t result;

	memset(&fwd, 0, sizeof(fwd));
	memset(&match, 0, sizeof(match));

	result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		return result;
	}

	result = set_flow_pipe_cfg(pipe_cfg, "ROOT_ROCEV2_PIPE", DOCA_FLOW_PIPE_CONTROL, true);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to configure pipe: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, FLOW_DSCP_ROOT_NUM_ENTRIES);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set number of entries: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set pipe domain: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_create(pipe_cfg, NULL, NULL, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create root RoCEv2 pipe: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	doca_flow_pipe_cfg_destroy(pipe_cfg);
	pipe_cfg = NULL;

	/* Route all ingress traffic to the non-root classifier pipe. */
	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = next_pipe;
	result = doca_flow_pipe_control_add_entry(0,
						  0,
						  *pipe,
						  &match,
						  NULL,
						  NULL,
						  NULL,
						  NULL,
						  NULL,
						  NULL,
						  &fwd,
						  status,
						  NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add RoCEv2 root entry: %s", doca_error_get_descr(result));
		doca_flow_pipe_destroy(*pipe);
		*pipe = NULL;
		return result;
	}

	return DOCA_SUCCESS;

destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

static void print_dscp_stats(struct dscp_stats_context *ctx)
{
	doca_error_t result;
	struct doca_flow_resource_query stats = {0};

	result = doca_flow_resource_query_entry(ctx->dscp_entry, &stats);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to query DSCP %u entry: %s", ctx->dscp, doca_error_get_descr(result));
		return;
	}

	DOCA_LOG_INFO("RoCEv2 DSCP=%u -> packets=%lu bytes=%lu",
		      ctx->dscp,
		      (unsigned long)stats.counter.total_pkts,
		      (unsigned long)stats.counter.total_bytes);

	result = doca_flow_resource_query_entry(ctx->other_dscp_entry, &stats);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to query non-DSCP entry: %s", doca_error_get_descr(result));
		return;
	}

	DOCA_LOG_INFO("RoCEv2 DSCP!=%u -> packets=%lu bytes=%lu",
		      ctx->dscp,
		      (unsigned long)stats.counter.total_pkts,
		      (unsigned long)stats.counter.total_bytes);

}

static void print_dscp_stats_wrapper(void *context)
{
	struct dscp_stats_context *ctx = (struct dscp_stats_context *)context;
	print_dscp_stats(ctx);
}

doca_error_t flow_dscp(int nb_queues, struct flow_switch_ctx *ctx, uint8_t dscp)
{
	int nb_ports;
	struct flow_resources resource = {
		.mode = DOCA_FLOW_RESOURCE_MODE_PORT,
		.nr_counters = FLOW_DSCP_NUM_COUNTERS,
	};
	uint32_t nr_shared_resources[SHARED_RESOURCE_NUM_VALUES] = {0};
	struct doca_flow_port *switch_port = NULL;
	struct entries_status status = {0};
	struct doca_flow_target *kernel_target;
	struct doca_flow_pipe *root_pipe = NULL;
	struct doca_flow_pipe *dscp_pipe = NULL;
	struct doca_flow_pipe_entry *dscp_entry = NULL;
	struct doca_flow_pipe_entry *other_dscp_entry = NULL;
	struct dscp_stats_context stats_ctx = {.dscp = dscp};
	doca_error_t result;

	if (ctx == NULL) {
		DOCA_LOG_ERR("Invalid switch context");
		return DOCA_ERROR_INVALID_VALUE;
	}
	nb_ports = ctx->devs_ctx.nb_ports;
	if (nb_ports <= 0) {
		DOCA_LOG_ERR("Invalid number of switch ports: %d", nb_ports);
		return DOCA_ERROR_INVALID_VALUE;
	}

	struct doca_flow_port *ports[nb_ports];
	uint32_t actions_mem_size[nb_ports];

	result = init_doca_flow(nb_queues, "switch,hws,isolated", &resource, nr_shared_resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_error_get_descr(result));
		return result;
	}

	ARRAY_INIT(actions_mem_size, ACTIONS_MEM_SIZE(FLOW_DSCP_NUM_ENTRIES));
	result = init_doca_flow_switch_ports(ctx->devs_ctx.devs_manager,
					     ctx->devs_ctx.nb_devs,
					     ports,
					     nb_ports,
					     actions_mem_size,
					     &resource);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA ports: %s", doca_error_get_descr(result));
		doca_flow_destroy();
		return result;
	}

	switch_port = doca_flow_port_switch_get(ports[0]);
	if (switch_port == NULL) {
		DOCA_LOG_ERR("Failed to get switch port");
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return DOCA_ERROR_BAD_STATE;
	}

	result = doca_flow_get_target(DOCA_FLOW_TARGET_KERNEL, &kernel_target);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get kernel target: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	result = create_rocev2_dscp_pipe(switch_port,
					 kernel_target,
					 dscp,
					 &status,
					 &dscp_pipe,
					 &dscp_entry,
					 &other_dscp_entry);
	if (result != DOCA_SUCCESS) {
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	result = create_root_rocev2_pipe(switch_port, dscp_pipe, &status, &root_pipe);
	if (result != DOCA_SUCCESS) {
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	result = flow_process_entries(switch_port, &status, FLOW_DSCP_NUM_ENTRIES);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process entries: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}

	stats_ctx.dscp_entry = dscp_entry;
	stats_ctx.other_dscp_entry = other_dscp_entry;
	flow_wait_for_packets(FLOW_DSCP_WAIT_TIME_SEC, print_dscp_stats_wrapper, &stats_ctx);

	result = stop_doca_flow_ports(nb_ports, ports);
	doca_flow_destroy();
	return result;
}
