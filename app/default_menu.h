#ifndef __DEFAULT_MENU_H__
#define __DEFAULT_MENU_H__

#include "stackmenu.h"

#define DEFAULT_MENU \
	{ "*", " Device & Platform information", NULL, run_update, NULL }, \
	{ "pi", "- Platform ID", NULL, NULL, data_platform_id }, \
	{ "mf", "- Manufacturer Name", NULL, NULL, data_mf_name }, \
	{ "dn", "- Device Name", NULL, NULL, data_device_name }, \
	{ "dt", "- Device Type", NULL, NULL, data_device_type }, \
	{ "^di", "- Device UUID", NULL, NULL, data_device_id }, \
	{ "log", "Log system", NULL, run_logsystem, data_logsystem }, \
	{ "-", NULL, }

static char data_logsystem[MENU_DATA_SIZE] = "syslog";

#ifdef DEFAULT_PLATFORM_ID
static char data_platform_id[MENU_DATA_SIZE] = DEFAULT_PLATFORM_ID;
#else
static char data_platform_id[MENU_DATA_SIZE] = "C0FFEE00-BAB0-BEEF-CODE-000000000000";
#endif

#ifdef DEFAULT_MF_NAME
static char data_mf_name[MENU_DATA_SIZE] = DEFAULT_MF_NAME;
#else
static char data_mf_name[MENU_DATA_SIZE] = "webispy";
#endif

#ifdef DEFAULT_DEVICE_NAME
static char data_device_name[MENU_DATA_SIZE] = DEFAULT_DEVICE_NAME;
#else
static char data_device_name[MENU_DATA_SIZE] = "myapplication";
#endif

#ifdef DEFAULT_DEVICE_TYPE
static char data_device_type[MENU_DATA_SIZE] = DEFAULT_DEVICE_TYPE;
#else
static char data_device_type[MENU_DATA_SIZE] = "oic.d.light";
#endif

#ifdef DEFAULT_DEVICE_ID
static char data_device_id[MENU_DATA_SIZE] = DEFAULT_DEVICE_ID;
#else
static char data_device_id[MENU_DATA_SIZE] = "00000000-0000-0000-0000-000000000000";
#endif


static int run_update(Stackmenu *mm, StackmenuItem *menu, void *user_data)
{
	if (iotivity_is_running() == 0)
		return 0;

	return iotivity_get_uuid(data_device_id, MENU_DATA_SIZE);
}

static int run_logsystem(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	if (!g_strcmp0(data_logsystem, "syslog"))
		iotivity_logsystem_syslog();
	else if (!g_strcmp0(data_logsystem, "stdout"))
		iotivity_logsystem_stdout();
	else {
		printf(ANSI_COLOR_RED);
		printf("\nInvalid input '%s'\n", data_logsystem);
		printf("Only 'syslog' or 'stdout' is allowed\n");
		printf(ANSI_COLOR_NORMAL);
		snprintf(data_logsystem, MENU_DATA_SIZE, "syslog");
		return run_logsystem(mm, menu, user_data);
	}

	return 0;
}

#endif
