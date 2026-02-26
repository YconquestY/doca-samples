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

#include <stdlib.h>
#include <string.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>

#include <flow_common.h>
#include <flow_switch_common.h>

#include <dpdk_utils.h>

DOCA_LOG_REGISTER(FLOW_DSCP::MAIN);

#define FLOW_DSCP_MIN (0)
#define FLOW_DSCP_MAX (63)

struct flow_dscp_cfg {
	struct flow_switch_ctx switch_ctx;
	int dscp;
};

/* Sample's Logic */
doca_error_t flow_dscp(int nb_queues, struct flow_switch_ctx *ctx, uint8_t dscp);

static doca_error_t dscp_callback(void *param, void *opaque)
{
	struct flow_dscp_cfg *cfg = (struct flow_dscp_cfg *)opaque;
	int value = *(int *)param;

	if (value < FLOW_DSCP_MIN || value > FLOW_DSCP_MAX) {
		DOCA_LOG_ERR("DSCP must be in range [%d, %d]", FLOW_DSCP_MIN, FLOW_DSCP_MAX);
		return DOCA_ERROR_INVALID_VALUE;
	}

	cfg->dscp = value;
	return DOCA_SUCCESS;
}

static doca_error_t register_sample_params(void)
{
	doca_error_t result;
	struct doca_argp_param *dscp_param;

	result = doca_argp_param_create(&dscp_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create dscp parameter: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(dscp_param, "d");
	doca_argp_param_set_long_name(dscp_param, "dscp");
	doca_argp_param_set_arguments(dscp_param, "<0-63>");
	doca_argp_param_set_description(dscp_param, "DSCP value to monitor");
	doca_argp_param_set_callback(dscp_param, dscp_callback);
	doca_argp_param_set_type(dscp_param, DOCA_ARGP_TYPE_INT);
	doca_argp_param_set_mandatory(dscp_param);
	result = doca_argp_register_param(dscp_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register dscp parameter: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv)
{
	doca_error_t result;
	struct doca_log_backend *sdk_log;
	int exit_status = EXIT_FAILURE;
	struct flow_dscp_cfg app_cfg = {.dscp = -1};
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 0,
		.port_config.nb_queues = 1,
		.port_config.switch_mode = 1,
	};

	/* Register a logger backend */
	result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	/* Register a logger backend for internal SDK errors and warnings */
	result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
	if (result != DOCA_SUCCESS)
		goto sample_exit;
	result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	DOCA_LOG_INFO("Starting the sample");

	result = doca_argp_init(NULL, &app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		goto sample_exit;
	}

	result = register_sample_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register sample parameters: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	result = register_doca_flow_switch_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register flow switch parameters: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	result = register_flow_stats_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register stats parameters: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	doca_argp_set_dpdk_program(flow_init_dpdk);
	app_cfg.switch_ctx.devs_ctx.default_dev_args = FLOW_SWITCH_DEV_ARGS;
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	if (app_cfg.switch_ctx.devs_ctx.nb_ports == 0) {
		DOCA_LOG_ERR("At least one flow device (and optional representors) must be provided");
		goto argp_cleanup;
	}

	result = init_doca_flow_devs(&app_cfg.switch_ctx.devs_ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init flow devices: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	dpdk_config.port_config.nb_ports = app_cfg.switch_ctx.devs_ctx.nb_ports;

	/* update queues and ports */
	result = dpdk_queues_and_ports_init(&dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update ports and queues");
		goto dpdk_cleanup;
	}

	/* run sample */
	result = flow_dscp(dpdk_config.port_config.nb_queues, &app_cfg.switch_ctx, (uint8_t)app_cfg.dscp);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("flow_dscp() encountered an error: %s", doca_error_get_descr(result));
		goto dpdk_ports_queues_cleanup;
	}

	exit_status = EXIT_SUCCESS;

dpdk_ports_queues_cleanup:
	dpdk_queues_and_ports_fini(&dpdk_config);
dpdk_cleanup:
	dpdk_fini();
argp_cleanup:
	doca_argp_destroy();
sample_exit:
	destroy_doca_flow_devs(&app_cfg.switch_ctx.devs_ctx);
	if (exit_status == EXIT_SUCCESS)
		DOCA_LOG_INFO("Sample finished successfully");
	else
		DOCA_LOG_INFO("Sample finished with errors");
	return exit_status;
}
