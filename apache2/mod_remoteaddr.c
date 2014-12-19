/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/*
 * @file: mod_remoteaddr.c
 * @brief: REMOTE_ADDR environment variable replacement module
 * @author: YoungJoo.Kim <vozlt@vozlt.com>
 * @version:
 * @date:
 *
 * mod_remoteaddr.c : REMOTE_ADDR Environment Variable Replacement Module
 *
 * This module provides a hook that is replace by user-defined http header variable's value from REMOTE_ADDR environment variable's value.
 * REMOTE_ADDR environment variable's value is changed to user-defined http header variable's value when this module is enabled.
 * User-defined http header variable name is like X-Forwarded-For(XFF), X-{YOUR_DEFINED}-For, {YOUR_DEFINED}.
 *
 * - Add module(apxs)
 * [root@root mod_remoteaddr]# apxs -iac mod_remoteaddr.c
 *
 * - Configuration(httpd.conf)
 *
 * AddModule mod_remoteaddr.c
 *
 * <IfModule mod_remoteaddr.c>
 *		# Hooking Header Name (TAKE12 - one or two arguments)
 *		HookVarName         X-Forwarded-For
 *
 *		# Select only one IP address (LEFT|RIGHT)
 *		SelectX				LEFT
 *
 *		# Original IP Save
 *		SaveVarName         REMOTE_ADDR_SAVE
 *
 *		# Hooking ($REMOTE_ADDR, access_log)
 *		IntVarHook        On
 *
 *		# Scoreboard Hooking (server-status)
 *		ScoreVarHook      On
 * </IfModule>
 *
 *
 * Link :
 * 			http://httpd.apache.org/dev/apidoc
 * 			http://httpd.apache.org/docs/2.0/developer
 *
 *
 */


#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_mpm.h"
#include "scoreboard.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "apr_strings.h"

#include <arpa/inet.h>

#define REMOTEADDR_DEBUG APLOG_MARK, APLOG_DEBUG, APR_SUCCESS

module AP_MODULE_DECLARE_DATA remoteaddr_module;

static int replace_scoreboard_client(const char *client); 

static int replace_scoreboard_client(const char *client) {
	apr_proc_t procnew;
	int x, y;
	int max_thread_limit;
	worker_score *ws_record;

	procnew.pid = getpid();
	x = find_child_by_pid(&procnew);

	if (x >= 0) {
		ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &max_thread_limit);
		for (y = 0; y < max_thread_limit; ++y) {
			ws_record = ap_get_scoreboard_worker(x, y);
			if (ws_record->access_count == 0 &&
					(ws_record->status == SERVER_READY ||
					 ws_record->status == SERVER_DEAD)) {
				continue;
			}
			/* ws_record->client == ap_scoreboard_image->servers[x][y].client */
			apr_cpystrn(ws_record->client, client, sizeof(ws_record->client));
		}
	}
	return x;
}

typedef struct {
	/* user define header name (Example: X-Forwarded-For) */
	const char *hook_var_name_v;

	const char *hook_var_name_v1;
	
	/*  Original REMOTE_ADDR copy (Example: REMOTE_ADDR_SAVE) */
	const char *save_var_name_v;

	/* Select only one IP address */
	unsigned int select_x_v:1;

	/* Apache Environment Hook set */
	unsigned int env_var_hook_set:1;

	/* r->connection->remote_ip Hook set */
	unsigned int int_var_hook_set:1;

	/* Server-Status Scoreboard Hook set */
	unsigned int score_var_hook_set:1;

} remoteaddr_config;

typedef struct {
	const char *save_remote_ip;
	request_rec *r;
} remoteaddr_cleanup_rec;

static void *remoteaddr_create_server_config(apr_pool_t *p, server_rec *s)
{
	remoteaddr_config *scfg = (remoteaddr_config *)apr_pcalloc(p, sizeof(remoteaddr_config));
	return (void *) scfg;
}

static const char *set_hook_var_name(cmd_parms *cmd, void *mconfig, const char *value, const char *value1)
{
	remoteaddr_config *scfg = (remoteaddr_config *) ap_get_module_config(cmd->server->module_config, &remoteaddr_module);

	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

	if (err != NULL) {
		return err;
	}

	scfg->hook_var_name_v = value;
	scfg->hook_var_name_v1 = value1;

	return NULL;
}

static const char *set_select_x(cmd_parms *cmd, void *dcfg, const char *value)
{
	remoteaddr_config *scfg = (remoteaddr_config *) ap_get_module_config(cmd->server->module_config, &remoteaddr_module);

	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

	if (err != NULL) {
		return err;
	}

	scfg->select_x_v = (!strcasecmp(value, "left")) ? 1 : 0;

	return NULL;
}

static const char *set_save_var_name(cmd_parms *cmd, void *mconfig, const char *value)
{
	remoteaddr_config *scfg = (remoteaddr_config *) ap_get_module_config(cmd->server->module_config, &remoteaddr_module);

	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

	if (err != NULL) {
		return err;
	}

	scfg->save_var_name_v = value;

	return NULL;
}

static const char *set_env_var_hook(cmd_parms *cmd, void *mconfig, const char *value)
{
	remoteaddr_config *scfg = (remoteaddr_config *) ap_get_module_config(cmd->server->module_config, &remoteaddr_module);

	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}

	scfg->env_var_hook_set = (!strcasecmp(value, "on")) ? 1 : 0;

	return NULL;
}

static const char *set_int_var_hook(cmd_parms *cmd, void *mconfig, const char *value)
{
	remoteaddr_config *scfg = (remoteaddr_config *) ap_get_module_config(cmd->server->module_config, &remoteaddr_module);

	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}

	scfg->int_var_hook_set = (!strcasecmp(value, "on")) ? 1 : 0;

	return NULL;
}

static const char *set_score_var_hook(cmd_parms *cmd, void *mconfig, const char *value)
{
	remoteaddr_config *scfg = (remoteaddr_config *) ap_get_module_config(cmd->server->module_config, &remoteaddr_module);

	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}

	scfg->score_var_hook_set = (!strcasecmp(value, "on")) ? 1 : 0;

	return NULL;
}

/* See http_config.h */
static const command_rec remoteaddr_cmds[] = {
	AP_INIT_TAKE12
	(   
		"HookVarName",					/* directive name */
		set_hook_var_name,				/* user function pointer */
		NULL,							/* argument to include in call */
		RSRC_CONF,						/* *.conf outside <Directory> or <Location> */
		"Environment Variable Name which user define headers(Example: X-Forwarded-For)" /* directive description */
	),

	AP_INIT_TAKE1
	(   
		"SelectX",
		set_select_x,
		NULL,
		RSRC_CONF,
		"Select only one IP address."
	),

	AP_INIT_TAKE1
	(   
		"SaveVarName",
		set_save_var_name,
		NULL,
		RSRC_CONF,
		"Original REMOTE_ADDR Save Variable."
	),

	AP_INIT_TAKE1
	(   
		"EnvVarHook",
		set_env_var_hook,
		NULL,
		RSRC_CONF,
		"Apache Environment Variable Hook set."
	),

	AP_INIT_TAKE1
	(   
		"IntVarHook",
		set_int_var_hook,
		NULL,
		RSRC_CONF,
		"Apache Internal Variable Hook set."
	),

	AP_INIT_TAKE1
	(   
		"ScoreVarHook",
		set_score_var_hook,
		NULL,
		RSRC_CONF,
		"Apache server-status Hook set."
	),

	{NULL}
};


static apr_status_t remoteaddr_cleanup(void *data) {
	remoteaddr_cleanup_rec *rcr = (remoteaddr_cleanup_rec *)data;
	rcr->r->connection->remote_ip = apr_pstrdup(rcr->r->connection->pool, rcr->save_remote_ip);
	rcr->r->connection->remote_addr->sa.sin.sin_addr.s_addr = inet_addr(rcr->r->connection->remote_ip);
	return APR_SUCCESS;
}

static int remoteaddr_match_headers(request_rec *r)
{
	struct in_addr inp;
	const char *val = NULL, *val_s = NULL;
	const char *accept_line = NULL;
	int is_ip;

	remoteaddr_config *scfg = (remoteaddr_config *) ap_get_module_config(r->server->module_config, &remoteaddr_module);

	/* If (HookVarName) routine */
	if (scfg->hook_var_name_v) {
		accept_line = apr_table_get(r->headers_in, scfg->hook_var_name_v);

		if (!accept_line)
			accept_line = apr_table_get(r->headers_in, scfg->hook_var_name_v1);

		if (accept_line) {
			/* LEFT IP */
			if (scfg->select_x_v) {
				val = ap_get_token(r->pool, &accept_line, 1);
			}
			/* RIGHT IP */
			else {
				while (*accept_line && (val = ap_get_token(r->pool, &accept_line, 1))) {
					if (*accept_line == ',') ++accept_line;
				}
			}
		} else {
			return DECLINED;
		}

		is_ip = inet_aton(val ? val : "", &inp);

		/* If (value is exists such as X-Forwarded-For or user define header) routine */
		if (is_ip) {
			remoteaddr_cleanup_rec *rcr = (remoteaddr_cleanup_rec *)apr_pcalloc(r->pool, sizeof(remoteaddr_cleanup_rec));
			rcr->save_remote_ip = apr_pstrdup(r->connection->pool, r->connection->remote_ip);
			rcr->r = r;
			apr_pool_cleanup_register(r->pool, (void *)rcr, remoteaddr_cleanup, apr_pool_cleanup_null);

			/* Original $REMOTE_ADDR save routine */
			if (scfg->save_var_name_v) {
				val_s = apr_table_get(r->subprocess_env, scfg->save_var_name_v);
				if (val_s == NULL) {
					apr_table_setn(r->subprocess_env, scfg->save_var_name_v, rcr->save_remote_ip);
				}
			}
			/* Invalid Hooking routine
			 * This is invalid becasue it is reset by other modules such as mod_cgi or mod_php or etc.
			 * $REMOTE_ADDR set in ap_add_common_vars().
			 */
			if (scfg->env_var_hook_set) {
				apr_table_setn(r->subprocess_env, "REMOTE_ADDR", val);
			}
			/* Hooking routine */
			if (scfg->int_var_hook_set) {
				r->connection->remote_ip = (char *)val;
				r->connection->remote_addr->sa.sin.sin_addr.s_addr = apr_inet_addr(r->connection->remote_ip);
			}
			/* If (Scoreboard hook is not run) routine */
			if (!scfg->score_var_hook_set) {
				if (val_s) {
					replace_scoreboard_client(val_s);
				}
			}
			if (scfg->score_var_hook_set && !scfg->int_var_hook_set) {
				if (val) {
					replace_scoreboard_client(val);
				}
			}
		} 
	}
	/* Debug routine */
	ap_log_error(REMOTEADDR_DEBUG, r->server,
			"%s["
			"val:%s|"
			"r->connection->remote_ip:%s|"
			"scfg->hook_var_name_v:%s|"
			"scfg->hook_var_name_v1:%s|"
			"scfg->save_var_name_v:%s]"
			, __func__, val, r->connection->remote_ip, scfg->hook_var_name_v, scfg->hook_var_name_v1,
			scfg->save_var_name_v);

	return DECLINED;
}

static void remoteaddr_register_hooks(apr_pool_t *p)
{   
	ap_hook_post_read_request(remoteaddr_match_headers, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA remoteaddr_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,								/* create per-dir    config structures */
    NULL,								/* merge  per-dir    config structures */
    remoteaddr_create_server_config,	/* create per-server config structures */
    NULL,								/* merge  per-server config structures */
    remoteaddr_cmds,					/* table of config file commands */
    remoteaddr_register_hooks,			/* register hooks */
};
