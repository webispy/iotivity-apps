#include "common.h"
#include "stackmenu.h"
#include "security.h"
#include "crudn.h"

#ifndef DEFAULT_DEVICE_NAME
#define DEFAULT_DEVICE_NAME "myclient"
#endif

#include "default_menu.h"

#define TIMEOUT_DISCOVERY 3

static OCPlatformInfo pi = {
	.platformID = data_platform_id,
	.manufacturerName = data_mf_name
};

struct crudn_data {
	OCDevAddr addr;
	OCDevAddr addr_next;
	int is_dual_mode;
	char uri[MENU_DATA_SIZE];
};

static StackmenuItem menu_dd[MENU_MAX_ITEMS];
static StackmenuItem menu_client_main[];

static guint timer_discover_retry;

static OCPayload *_create_payload_with_userinput(void)
{
	OCRepPayload *p;
	char buf[255];

	p = OCRepPayloadCreate();
	if (!p) {
		error("OCRepPayloadCreate() failed");
		return NULL;
	}

	info("Only support BOOLEAN value. Please input '0' or '1'.");
	printf(" value = ? ");
	if (fgets(buf, 255, stdin) == NULL) {
		error("fgets() failed");
		OCRepPayloadDestroy(p);
		return NULL;
	}

	OCRepPayloadSetPropBool(p, "value", atoi(buf));

	iotivity_payload_dump((OCPayload *)p);

	return (OCPayload *)p;
}

static OCStackApplicationResult _request_cb(void *ctx, OCDoHandle handle,
		OCClientResponse *resp)
{
	if (!resp) {
		error("response is NULL");
		return OC_STACK_DELETE_TRANSACTION;
	}

	iotivity_show_result(ctx, resp->result);
	iotivity_payload_dump(resp->payload);

	return OC_STACK_KEEP_TRANSACTION;
}

static int _select_eps_mode(const char *uri)
{
	char buf[255];

	info("'%s' support both SECURE and NON-SECURE eps.", uri);
	printf("Send request to SECURE eps ? (Yn) ");

	if (fgets(buf, 255, stdin) == NULL)
		return 0;

	if (strlen(buf) == 2 && buf[1] == '\n'
			&& (buf[0] == 'N' || buf[0] == 'n')) {
		info("- Send to NON-SECURE eps\n");
		return 1;
	}

	return 0;
}

static int run_get(Stackmenu *mm, StackmenuItem *menu, void *user_data)
{
	OCStackResult ret;
	OCDoHandle handle = NULL;
	OCCallbackData cbd;
	struct crudn_data *data = menu->custom_data;
	OCDevAddr *addr = &data->addr;

	cbd.cb = _request_cb;
	cbd.context = "OCDoRequest(GET)";
	cbd.cd = NULL;

	if (data->is_dual_mode && _select_eps_mode(data->uri) == 1)
		addr = &data->addr_next;

	iotivity_show_addr("OCDoRequest()", addr);

	ret = OCDoRequest(&handle, OC_REST_GET, data->uri, addr, NULL,
			CT_ADAPTER_IP, OC_LOW_QOS, &cbd, NULL, 0);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCDoRequest()", ret);
		return -1;
	}

	info("Request uri='%s', handle = %p", data->uri, handle);

	return 0;
}

static int run_put(Stackmenu *mm, StackmenuItem *menu, void *user_data)
{
	OCStackResult ret;
	OCDoHandle handle = NULL;
	OCCallbackData cbd;
	OCPayload *payload;
	struct crudn_data *data = menu->custom_data;
	OCDevAddr *addr = &data->addr;

	payload = _create_payload_with_userinput();
	if (!payload)
		return -1;

	cbd.cb = _request_cb;
	cbd.context = "OCDoRequest(PUT)";
	cbd.cd = NULL;

	if (data->is_dual_mode && _select_eps_mode(data->uri) == 1)
		addr = &data->addr_next;

	iotivity_show_addr("OCDoRequest()", addr);

	ret = OCDoRequest(&handle, OC_REST_PUT, data->uri, addr, payload,
			CT_ADAPTER_IP, OC_LOW_QOS, &cbd, NULL, 0);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCDoRequest()", ret);
		return -1;
	}

	info("Request uri='%s', handle = %p", data->uri, handle);

	return 0;
}

static int run_post(Stackmenu *mm, StackmenuItem *menu, void *user_data)
{
	OCStackResult ret;
	OCDoHandle handle = NULL;
	OCCallbackData cbd;
	OCPayload *payload;
	struct crudn_data *data = menu->custom_data;
	OCDevAddr *addr = &data->addr;

	payload = _create_payload_with_userinput();
	if (!payload)
		return -1;

	cbd.cb = _request_cb;
	cbd.context = "OCDoRequest(POST)";
	cbd.cd = NULL;

	if (data->is_dual_mode && _select_eps_mode(data->uri) == 1)
		addr = &data->addr_next;

	iotivity_show_addr("OCDoRequest()", addr);

	ret = OCDoRequest(&handle, OC_REST_POST, data->uri, addr,
			payload, CT_ADAPTER_IP, OC_LOW_QOS, &cbd, NULL, 0);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCDoRequest()", ret);
		return -1;
	}

	info("Request uri='%s', handle = %p", data->uri, handle);

	return 0;
}

static int run_delete(Stackmenu *mm, StackmenuItem *menu, void *user_data)
{
	OCStackResult ret;
	OCDoHandle handle = NULL;
	OCCallbackData cbd;
	struct crudn_data *data = menu->custom_data;
	OCDevAddr *addr = &data->addr;

	cbd.cb = _request_cb;
	cbd.context = "OCDoRequest(DELETE)";
	cbd.cd = NULL;

	if (data->is_dual_mode && _select_eps_mode(data->uri) == 1)
		addr = &data->addr_next;

	iotivity_show_addr("OCDoRequest()", addr);

	ret = OCDoRequest(&handle, OC_REST_DELETE, data->uri, addr, NULL,
			CT_ADAPTER_IP, OC_LOW_QOS, &cbd, NULL, 0);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCDoRequest()", ret);
		return -1;
	}

	info("Request uri='%s', handle = %p", data->uri, handle);

	return 0;
}

static struct crudn_data *_crudn_data_dup(struct crudn_data *data)
{
	struct crudn_data *tmp;

	if (!data)
		return NULL;

	tmp = calloc(1, sizeof(struct crudn_data));
	if (!tmp)
		return NULL;

	memcpy(&(tmp->addr), &(data->addr), sizeof(OCDevAddr));
	memcpy(&(tmp->addr_next), &(data->addr_next), sizeof(OCDevAddr));
	memcpy(&(tmp->uri), &(data->uri), strlen(data->uri));
	tmp->is_dual_mode = data->is_dual_mode;

	return tmp;
}

static void _add_crudn_menu(StackmenuItem *mnu, struct crudn_data *data,
		const char *uri)
{
	if (!mnu || !data)
		return;

	memset(data->uri, 0, sizeof(data->uri));
	memcpy(data->uri, uri, strlen(uri));

	mnu->sub_menu = calloc(1, sizeof(StackmenuItem) * 5);
	mnu->sub_menu[0].key = strdup("0");
	mnu->sub_menu[0].title = strdup("Get");
	mnu->sub_menu[0].callback = run_get;
	mnu->sub_menu[0].custom_data = _crudn_data_dup(data);
	mnu->sub_menu[0].custom_data_destroy_callback = free;
	mnu->sub_menu[1].key = strdup("1");
	mnu->sub_menu[1].title = strdup("Put");
	mnu->sub_menu[1].callback = run_put;
	mnu->sub_menu[1].custom_data = _crudn_data_dup(data);
	mnu->sub_menu[1].custom_data_destroy_callback = free;
	mnu->sub_menu[2].key = strdup("2");
	mnu->sub_menu[2].title = strdup("Post");
	mnu->sub_menu[2].callback = run_post;
	mnu->sub_menu[2].custom_data = _crudn_data_dup(data);
	mnu->sub_menu[2].custom_data_destroy_callback = free;
	mnu->sub_menu[3].key = strdup("3");
	mnu->sub_menu[3].title = strdup("Delete");
	mnu->sub_menu[3].callback = run_delete;
	mnu->sub_menu[3].custom_data = _crudn_data_dup(data);
	mnu->sub_menu[3].custom_data_destroy_callback = free;
}

static OCStackApplicationResult _discovery_cb(void *ctx, OCDoHandle handle,
		OCClientResponse *resp)
{
	OCDiscoveryPayload *payload = (OCDiscoveryPayload *)resp->payload;
	OCResourcePayload *rsrcs;
	OCEndpointPayload *eps;
	int maxcnt;
	int i;
	int is_secure;
	int is_nonsecure;
	char buf[256];
	char short_addr[MAX_ADDR_STR_SIZE];
	char *ifname_pos;
	StackmenuItem *mnu, *item_dlist;
	struct crudn_data extra_data;

	if (!payload) {
		dbg("no payload");
		return OC_STACK_KEEP_TRANSACTION;
	}

	if (!g_strcmp0(data_device_id, payload->sid))
		return OC_STACK_KEEP_TRANSACTION;

	i = stackmenu_item_count(menu_dd);
	if (i == MENU_MAX_ITEMS) {
		dbg("too many devices. skip '%s'", payload->sid);
		return OC_STACK_KEEP_TRANSACTION;
	}

	/* Remove network interface name */
	memcpy(short_addr, resp->devAddr.addr, MAX_ADDR_STR_SIZE);
	ifname_pos = strchr(short_addr, '%');
	if (ifname_pos)
		*ifname_pos = '\0';

	info("\nFound! %s (%s)", payload->sid, short_addr);

	if (strlen(short_addr) > 15)
		snprintf(buf, sizeof(buf), "%s ..%s", payload->sid,
				short_addr + (strlen(short_addr) - 15));
	else
		snprintf(buf, sizeof(buf), "%s %s", payload->sid, short_addr);

	/* Skip same UUID with network address */
	if (stackmenu_item_find_by_title(menu_dd, buf))
		return OC_STACK_KEEP_TRANSACTION;

	maxcnt = 0;
	for (rsrcs = payload->resources; rsrcs; rsrcs = rsrcs->next)
		maxcnt++;

	if (maxcnt == 0) {
		info("no resources");
		return OC_STACK_KEEP_TRANSACTION;
	}

	/* Enable the menu item - 'Discovered devices' */
	item_dlist = stackmenu_item_find(menu_client_main, "3");
	if (!item_dlist) {
		error("stackmenu_item_find() failed.");
		return -1;
	}

	stackmenu_item_enable(item_dlist);

	/* Add a discovered device to menu list */
	menu_dd[i].key = g_strdup_printf("%d", i);
	menu_dd[i].title = g_strdup(buf);

	info("- DevAddr: %s:[port=%d]", resp->devAddr.addr, resp->devAddr.port);
	iotivity_show_adapter("- ", resp->devAddr.adapter, NULL);
	iotivity_show_flags("- ", resp->devAddr.flags, NULL);

	menu_dd[i].sub_menu = calloc(1,
			sizeof(StackmenuItem) * (maxcnt + 1));

	info("- uri");

	maxcnt = 0;
	for (rsrcs = payload->resources; rsrcs; rsrcs = rsrcs->next, maxcnt++) {
		info("  - [%d] %s", maxcnt, rsrcs->uri);

		is_secure = 0;
		is_nonsecure = 0;
		memcpy(&(extra_data.addr), &(resp->devAddr), sizeof(OCDevAddr));

		for (eps = rsrcs->eps; eps; eps = eps->next) {
			printf("    - Endpoint: %s://%s:%u", eps->tps,
					eps->addr, eps->port);
			iotivity_show_flags(", ", eps->family, NULL);

			if ((eps->family & OC_FLAG_SECURE) == 0) {
				is_nonsecure = 1;
				memcpy(&(extra_data.addr_next),
						&(resp->devAddr),
						sizeof(OCDevAddr));
				extra_data.addr_next.port = eps->port;
				extra_data.addr_next.flags = eps->family;
				continue;
			}

			/* Change DevAddr to secure endpoints */
			is_secure = 1;
			extra_data.addr.port = eps->port;
			extra_data.addr.flags = eps->family | OC_FLAG_SECURE;
		}

		mnu = &menu_dd[i].sub_menu[maxcnt];
		mnu->key = g_strdup_printf("%d", maxcnt);
		if (is_secure && is_nonsecure) {
			extra_data.is_dual_mode = 1;
			mnu->title = g_strdup_printf("%s (secure + non-secure)",
					rsrcs->uri);
		} else if (is_secure) {
			extra_data.is_dual_mode = 0;
			mnu->title = g_strdup_printf("%s (secure)", rsrcs->uri);
		} else {
			extra_data.is_dual_mode = 0;
			mnu->title = g_strdup_printf("%s", rsrcs->uri);
		}

		_add_crudn_menu(mnu, &extra_data, rsrcs->uri);
	}

	return OC_STACK_KEEP_TRANSACTION;
}

static int _start_discovery()
{
	OCStackResult ret;
	OCCallbackData cbd;

	cbd.cb = _discovery_cb;
	cbd.context = NULL;
	cbd.cd = NULL;

	ret = OCDoRequest(NULL, OC_REST_DISCOVER, OC_RSRVD_WELL_KNOWN_URI, NULL,
			NULL, CT_DEFAULT, OC_LOW_QOS, &cbd, NULL, 0);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCDoRequest()", ret);
		return -1;
	}

	return 0;
}

static gboolean on_timeout_discovery_check(gpointer user_data)
{
	StackmenuItem *item_dlist;

	item_dlist = stackmenu_item_find(menu_client_main, "3");
	if (stackmenu_item_is_enabled(item_dlist)) {
		info("\nDevice found. Stop discovery timer");
		timer_discover_retry = 0;
		return FALSE;
	}

	info("No devices. Retry discover");
	if (_start_discovery() < 0) {
		timer_discover_retry = 0;
		return FALSE;
	}

	/* Continue timer */
	return TRUE;
}

static int run_discovery(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	int i;
	StackmenuItem *item_dlist;

	if (iotivity_is_running() == 0) {
		info("Client is not running. Please run client.");
		return 0;
	}

	if (timer_discover_retry) {
		g_source_remove(timer_discover_retry);
		timer_discover_retry = 0;
	}

	/* Disable the menu item - 'Discovered devices' */
	item_dlist = stackmenu_item_find(menu_client_main, "3");
	if (!item_dlist) {
		error("stackmenu_item_find() failed.");
		return -1;
	}

	stackmenu_item_disable(item_dlist);

	for (i = 0; i < MENU_MAX_ITEMS; i++)
		stackmenu_item_clear(&menu_dd[i]);

	info("Start discovery every %d secs", TIMEOUT_DISCOVERY);
	if (_start_discovery() < 0)
		return -1;

	timer_discover_retry = g_timeout_add_seconds(TIMEOUT_DISCOVERY,
			on_timeout_discovery_check, NULL);

	return 0;
}

static int run_reset_svr(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	if (iotivity_is_running()) {
		info("Please run before start client.");
		return 0;
	}

	return svr_reset_client("svr_client/oic_svr_db.dat");
}

static int run_start_client(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	OCStackResult ret;
	OCResourceHandle device_h;

	if (iotivity_is_running()) {
		info("Client already running.");
		return 0;
	}

	ret = OCInit(NULL, 0, OC_CLIENT_SERVER);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCInit()", ret);
		return -1;
	}

	ret = OCSetPlatformInfo(pi);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCSetPlatformInfo()", ret);
		return -1;
	}

	device_h = OCGetResourceHandleAtUri(OC_RSRVD_DEVICE_URI);
	if (!device_h) {
		error("Can't find device handle");
		return -1;
	}

	OCBindResourceTypeToResource(device_h, data_device_type);
	OCSetPropertyValue(PAYLOAD_TYPE_DEVICE, OC_RSRVD_DEVICE_NAME,
			data_device_name);
	OCSetPropertyValue(PAYLOAD_TYPE_DEVICE, OC_RSRVD_SPEC_VERSION,
			DEFAULT_ICV);
	OCSetPropertyValue(PAYLOAD_TYPE_DEVICE, OC_RSRVD_DATA_MODEL_VERSION,
			DEFAULT_DMV);

	iotivity_start();

	run_update(NULL, NULL, NULL);

	info("Client started");

	run_update(NULL, NULL, NULL);
	info("UUID: %s", data_device_id);

	return 0;
}

static char key_dlist[3] = "^3";

static StackmenuItem menu_client_main[] = {
	DEFAULT_MENU,
	{ "0", "Reset SVR DB", NULL, run_reset_svr, NULL },
	{ "1", "Start client", NULL, run_start_client, NULL },
	{ "2", "Discovery", NULL, run_discovery, NULL },
	{ "-", NULL, },
	{ key_dlist, "Discovered devices", menu_dd, NULL, NULL },
	{ NULL, NULL, },
};

int main(int argc, char *argv[])
{
	GMainLoop *loop;
	Stackmenu *manager;

	loop = g_main_loop_new(NULL, FALSE);

	if (getenv("IOTIVITY_LOG_LEVEL") == NULL)
		setenv("IOTIVITY_LOG_LEVEL", "4", 1);

	info("\n Client (Build with IoTivity v%s)", IOTIVITY_VERSION);

	iotivity_logsystem_syslog();
	security_init("svr_client", CLIENT);

	manager = stackmenu_new(menu_client_main, loop);
	stackmenu_run(manager);

	g_main_loop_run(loop);

	iotivity_stop();

	security_exit();

	info("bye bye");

	return 0;
}
