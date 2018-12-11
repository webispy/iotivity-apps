#ifndef __IOTIVITY_APPS_COMMON_H__
#define __IOTIVITY_APPS_COMMON_H__

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <iotivity_config.h>
#include <ocstack.h>
#include <ocpayload.h>
#include <deviceonboardingstate.h>
#include <doxmresource.h>
#include <srmutility.h>
#include <ocprovisioningmanager.h>
#include <pmutility.h>
#include <coap/utlist.h>

#ifdef BACKEND_GLIB
#include <glib.h>
#endif

#define ANSI_COLOR_NORMAL       "\e[0m"

#define ANSI_COLOR_BLACK        "\e[0;30m"
#define ANSI_COLOR_RED          "\e[0;31m"
#define ANSI_COLOR_GREEN        "\e[0;32m"
#define ANSI_COLOR_BROWN        "\e[0;33m"
#define ANSI_COLOR_BLUE         "\e[0;34m"
#define ANSI_COLOR_MAGENTA      "\e[0;35m"
#define ANSI_COLOR_CYAN         "\e[0;36m"
#define ANSI_COLOR_LIGHTGRAY    "\e[0;37m"

#define ANSI_COLOR_DARKGRAY     "\e[1;30m"
#define ANSI_COLOR_LIGHTRED     "\e[1;31m"
#define ANSI_COLOR_LIGHTGREEN   "\e[1;32m"
#define ANSI_COLOR_YELLOW       "\e[1;33m"
#define ANSI_COLOR_LIGHTBLUE    "\e[1;34m"
#define ANSI_COLOR_LIGHTMAGENTA "\e[1;35m"
#define ANSI_COLOR_LIGHTCYAN    "\e[1;36m"
#define ANSI_COLOR_WHITE        "\e[1;37m"

#define dbg(fmt, args ...) fprintf(stdout, "<%s:%d> " fmt "\n", \
		__FILE__, __LINE__, ## args)
#define info(fmt, args ...) fprintf(stdout, fmt "\n", ## args)
#define error(fmt, args ...) fprintf(stdout, ANSI_COLOR_LIGHTRED "<%s:%d> " \
		fmt ANSI_COLOR_NORMAL "\n", __FILE__, __LINE__, ## args)

#ifndef DEFAULT_ICV
#define DEFAULT_ICV "ocf.1.3.0"
#endif

#ifndef DEFAULT_DMV
#define DEFAULT_DMV "ocf.res.1.3.0,ocf.sh.1.3.0"
#endif

int svr_reset_server(const char *path);
int svr_reset_client(const char *path);
int svr_reset_obt(const char *path);

void iotivity_payload_dump(OCPayload *payload);
void iotivity_show_result(const char *msg, OCStackResult result);
void iotivity_show_flags(const char *msg, OCTransportFlags flags,
		const char *msg_last);
void iotivity_show_adapter(const char *msg, OCTransportAdapter adapter,
		const char *msg_last);
void iotivity_show_connectivity_type(const char *msg, OCConnectivityType type,
		const char *msg_last);
void iotivity_show_addr(const char *msg, OCDevAddr *addr);

void iotivity_logsystem_syslog(void);
void iotivity_logsystem_stdout(void);
int iotivity_start(void);
int iotivity_stop(void);
int iotivity_is_running(void);
int iotivity_lock(void);
int iotivity_unlock(void);

int iotivity_get_uuid(char *out, size_t out_len);

#endif
