#include "common.h"
#include "stackmenu.h"
#include "security.h"
#include "crudn.h"

#ifndef DEFAULT_DEVICE_NAME
#define DEFAULT_DEVICE_NAME "myserver"
#endif

#ifndef DEFAULT_DEVICE_TYPE
#define DEFAULT_DEVICE_TYPE "oic.d.light"
#endif

#include "default_menu.h"

static char data_rsrc_rt[MENU_DATA_SIZE] = "oic.r.switch.binary";
static char data_rsrc_if[MENU_DATA_SIZE] = "oic.if.a";
static char data_rsrc_uri[MENU_DATA_SIZE] = "/light";
static char data_rsrc_value[MENU_DATA_SIZE] = "0";

static OCResourceHandle rsrc;

static OCPlatformInfo pi = {
	.platformID = data_platform_id,
	.manufacturerName = data_mf_name
};

static OCEntityHandlerResult on_get(OCEntityHandlerFlag flag,
		OCEntityHandlerRequest *req, void *user_data)
{
	OCEntityHandlerResponse resp;
	OCRepPayload *payload = NULL;
	OicSecDostype_t dos;

	if (GetDos(&dos) != OC_STACK_OK) {
		error("GetDos() failed.");
		return OC_EH_ERROR;
	}

	if (dos.state != DOS_RFNOP) {
		info("DOS(0x%X) is not Ready-For-Normal-Operation", dos.state);
		return OC_EH_ERROR;
	}

	info("\nReceived GET request");

	payload = OCRepPayloadCreate();
	OCRepPayloadAddResourceType(payload, data_rsrc_rt);
	OCRepPayloadAddInterface(payload, "oic.if.baseline");
	OCRepPayloadAddInterface(payload, data_rsrc_if);

	OCRepPayloadSetPropBool(payload, "value", atoi(data_rsrc_value));

	memset(&resp, 0, sizeof(OCEntityHandlerResponse));
	resp.requestHandle = req->requestHandle;
	resp.resourceHandle = req->resource;
	resp.ehResult = OC_EH_OK;
	resp.payload = (OCPayload *)payload;

	info("Send response (value=%s)", data_rsrc_value);

	if (OCDoResponse(&resp) != OC_STACK_OK) {
		error("OCDoResponse() failed");
		OCRepPayloadDestroy(payload);
		return OC_EH_ERROR;
	}

	OCRepPayloadDestroy(payload);

	return OC_EH_OK;
}

static OCEntityHandlerResult on_put_post(OCEntityHandlerFlag flag,
		OCEntityHandlerRequest *req, void *user_data)
{
	OCEntityHandlerResponse resp;
	OCRepPayload *payload = NULL;
	OicSecDostype_t dos;
	bool value;

	if (GetDos(&dos) != OC_STACK_OK) {
		error("GetDos() failed.");
		return OC_EH_ERROR;
	}

	if (dos.state != DOS_RFNOP) {
		info("DOS(0x%X) is not Ready-For-Normal-Operation", dos.state);
		return OC_EH_ERROR;
	}

	if (req->method == OC_REST_PUT)
		info("\nReceived PUT request");
	else if (req->method == OC_REST_POST)
		info("\nReceived POST request");

	payload = (OCRepPayload *)req->payload;
	OCRepPayloadGetPropBool(payload, "value", &value);
	snprintf(data_rsrc_value, MENU_DATA_SIZE, "%d", value);

	info("- value: %d", value);

	payload = OCRepPayloadCreate();
	OCRepPayloadAddResourceType(payload, data_rsrc_rt);
	OCRepPayloadAddInterface(payload, "oic.if.baseline");
	OCRepPayloadAddInterface(payload, data_rsrc_if);

	OCRepPayloadSetPropBool(payload, "value", atoi(data_rsrc_value));

	memset(&resp, 0, sizeof(OCEntityHandlerResponse));
	resp.requestHandle = req->requestHandle;
	resp.resourceHandle = req->resource;
	resp.ehResult = OC_EH_OK;
	resp.payload = (OCPayload *)payload;

	info("Send response (value=%s)", data_rsrc_value);

	if (OCDoResponse(&resp) != OC_STACK_OK) {
		error("OCDoResponse() failed");
		OCRepPayloadDestroy(payload);
		return OC_EH_ERROR;
	}

	OCRepPayloadDestroy(payload);

	return OC_EH_OK;
}

static OCEntityHandlerResult on_del(OCEntityHandlerFlag flag,
		OCEntityHandlerRequest *req, void *user_data)
{
	info("\nReceived DELETE request");
	info("Send FORBIDDEN response");

	return OC_EH_FORBIDDEN;
}

struct crudn_ops rsrc_ops = {
	.get = on_get,
	.put = on_put_post,
	.post = on_put_post,
	.del = on_del
};


static int run_reset_svr(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	if (iotivity_is_running()) {
		info("Please run before start server.");
		return 0;
	}

	return svr_reset_server("svr_server/oic_svr_db.dat");
}

static int run_start_server(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	OCStackResult ret;
	OCResourceHandle device_h;

	if (iotivity_is_running()) {
		info("Server already started");
		return 0;
	}

	ret = OCInit(NULL, 0, OC_SERVER);
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

	ret = OCCreateResource(&rsrc, data_rsrc_rt, data_rsrc_if, data_rsrc_uri,
			crudn_handler, &rsrc_ops, OC_DISCOVERABLE | OC_SECURE);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCCreateResource()", ret);
		return -1;
	}

	iotivity_start();

	info("Server started.");

	run_update(NULL, NULL, NULL);
	info("UUID: %s", data_device_id);

	return 0;
}

static StackmenuItem menu_server_main[] = {
	DEFAULT_MENU,
	{ "*", " Resource information" },
	{ "rt", "- Type", NULL, NULL, data_rsrc_rt },
	{ "ri", "- Interface", NULL, NULL, data_rsrc_if },
	{ "ru", "- Uri", NULL, NULL, data_rsrc_uri },
	{ "rv", "- Value - Boolean", NULL, NULL, data_rsrc_value },
	{ "-", NULL, },
	{ "0", "Reset SVR DB", NULL, run_reset_svr, NULL },
	{ "1", "Start server", NULL, run_start_server, NULL },
	{ NULL, NULL, },
};

int main(int argc, char *argv[])
{
	GMainLoop *loop;
	Stackmenu *manager;

	loop = g_main_loop_new(NULL, FALSE);

	if (getenv("IOTIVITY_LOG_LEVEL") == NULL)
		setenv("IOTIVITY_LOG_LEVEL", "4", 1);

	info("\n Server (Build with IoTivity v%s)", IOTIVITY_VERSION);

	iotivity_logsystem_syslog();
	security_init("svr_server", SERVER);

	manager = stackmenu_new(menu_server_main, loop);
	stackmenu_run(manager);

	g_main_loop_run(loop);

	iotivity_stop();

	security_exit();

	info("bye bye");

	return 0;
}
