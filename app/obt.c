#include "common.h"
#include "stackmenu.h"
#include "security.h"
#include "crudn.h"

#ifndef DEFAULT_DEVICE_NAME
#define DEFAULT_DEVICE_NAME "myobt"
#endif

#include "default_menu.h"

#define TIMEOUT_DISCOVER 5
#define TIMEOUT_SYNC_CALL 30

static char data_acl_href[MENU_DATA_SIZE] = "/light";
static char data_acl_rt[MENU_DATA_SIZE] = "oic.r.switch.binary";
static char data_acl_if[MENU_DATA_SIZE] = "oic.if.a";

static int sync_call_done;

static StackmenuItem menu_unowned[MENU_MAX_ITEMS];
static StackmenuItem menu_owned[MENU_MAX_ITEMS];
static StackmenuItem menu_obt_main[];

#define MSG_SELECT_SERVER "Select " ANSI_COLOR_LIGHTGREEN "server" \
	ANSI_COLOR_NORMAL " device number"
#define MSG_SELECT_CLIENT "Select " ANSI_COLOR_LIGHTGREEN "client" \
	ANSI_COLOR_NORMAL " device number"
#define MSG_RETRY_OTM "Network(UDP Packet) is not reliable.\n" \
	"Please try again with " ANSI_COLOR_CYAN \
	"'Discover unowned devices'" ANSI_COLOR_NORMAL ".\n" \
	"If the discover result is 'No devices', please run " \
	ANSI_COLOR_CYAN "'Reset SVR DB' " ANSI_COLOR_NORMAL "from both\n" \
	"onboarding tool and targets(server/client). and try again.\n"

static void _dump_device_list(OCProvisionDev_t *list)
{
	OCProvisionDev_t *tmp;
	char *id = NULL;
	int cnt = 0;

	for (tmp = list; tmp; tmp = tmp->next)
		cnt++;

	info("%d devices", cnt);
	for (tmp = list; tmp; tmp = tmp->next) {
		ConvertUuidToStr(&tmp->doxm->deviceID, &id);
		if (!id) {
			error("ConverUuidToStr() failed");
			continue;
		}

		info("Device %s:[port=%d]:[secure_port=%d]", id,
				tmp->endpoint.port, tmp->securePort);
		info(" - specVer: %s, oxmsel: %d, oxm_len: %zd", tmp->specVer,
				tmp->doxm->oxmSel, tmp->doxm->oxmLen);
		info(" - addr: %s", tmp->endpoint.addr);

		free(id);
		id = NULL;
	}
}

static OCProvisionDev_t *_clone_pdev(OCProvisionDev_t *orig)
{
	OCProvisionDev_t *tmp;

	if (!orig)
		return NULL;

	tmp = PMCloneOCProvisionDev(orig);
	if (!tmp) {
		error("PMCloneOCProvisionDev() failed.");
		return NULL;
	}

	if (!orig->doxm)
		return tmp;

	if (!orig->doxm->oxm)
		return tmp;

	tmp->doxm->oxmLen = orig->doxm->oxmLen;
	tmp->doxm->oxm = malloc(sizeof(OicSecOxm_t) * tmp->doxm->oxmLen);
	memcpy(tmp->doxm->oxm, orig->doxm->oxm,
			sizeof(OicSecOxm_t) * tmp->doxm->oxmLen);

	return tmp;
}

static OCProvisionDev_t *_get_device_list(OCProvisionDev_t *list)
{
	OCProvisionDev_t *target_list = NULL;
	OCProvisionDev_t *tmp, *cur;
	int cnt = 1;

	if (!list) {
		info("No device list");
		return NULL;
	}

	target_list = _clone_pdev(list);
	list = list->next;

	/*
	 * Remove same UUID
	 */
	cur = target_list;
	for (; list; list = list->next) {
		for (tmp = target_list; tmp; tmp = tmp->next) {
			if (memcmp(&list->doxm->deviceID, &tmp->doxm->deviceID,
					sizeof(OicUuid_t)) == 0)
				break;
		}

		if (tmp == NULL) {
			cur->next = _clone_pdev(list);
			cur = cur->next;
			cnt++;
		}
	}

	return target_list;
}

static void _wait_sync_call(const char *msg, const char *msg_retry)
{
	int cnt;
	OCStackResult ret;

	info("Wait %d seconds for %s", TIMEOUT_SYNC_CALL, msg);

	for (cnt = 0; cnt < TIMEOUT_SYNC_CALL; cnt++) {
		ret = OCProcess();
		if (ret != OC_STACK_OK) {
			iotivity_show_result("OCProcess()", ret);
			break;
		}

		if (sync_call_done == 1)
			break;

		printf(".");
		fflush(stdout);
		sleep(1);
	}

	if (cnt == TIMEOUT_SYNC_CALL)
		info("%s Timeout.", msg);

	if (sync_call_done == 0 && msg_retry)
		info("%s", msg_retry);
}

static StackmenuItem *_input_device_number(StackmenuItem *menu,
		const char *msg)
{
	char buf[255] = {0, };

	printf("%s > ", msg);
	if (fgets(buf, 255, stdin) == NULL) {
		error("fgets() failed");
		return NULL;
	}

	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = '\0';

	return stackmenu_item_find(menu, buf);
}

static void _provision_cb(void *ctx, size_t n_res,
		OCProvisionResult_t *arr, bool result)
{
	sync_call_done = 1;

	if (result != 0)
		error("%s failed(%d)", (char *)ctx, result);
	else
		info("\n%s success (%zd devices)", (char *)ctx, n_res);
}

static int run_ownership(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	OCStackResult ret;
	OCProvisionDev_t *list;

	if (iotivity_is_running() == 0) {
		info("onboarding client is not running.");
		return -1;
	}

	list = menu->custom_data;
	if (!list) {
		error("Please discover first");
		return -1;
	}

	list->next = NULL;

	info("Start OTM");

	sync_call_done = 0;

	iotivity_lock();
	ret = OCDoOwnershipTransfer("OTM", list, _provision_cb);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCDoOwnershipTransfer()", ret);
		iotivity_unlock();
		return -1;
	}

	_wait_sync_call("OTM", MSG_RETRY_OTM);

	iotivity_unlock();

	return 0;
}

static int run_cred(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	StackmenuItem *dev1, *dev2;
	OCStackResult ret;

	info("You should select 2 devices.");

	dev1 = _input_device_number(menu_owned,
			"Select target device-1 number");
	if (!dev1) {
		info("Can't find device");
		return 0;
	}

	dev2 = _input_device_number(menu_owned,
			"Select target device-2 number");
	if (!dev2) {
		info("Can't find device");
		return 0;
	}

	sync_call_done = 0;

	iotivity_lock();
	ret = OCProvisionCredentials("Provision Credentials",
			SYMMETRIC_PAIR_WISE_KEY, 16, dev1->custom_data,
			dev2->custom_data, _provision_cb);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCProvisionCredentials()", ret);
		iotivity_unlock();
		return -1;
	}
	iotivity_unlock();

	_wait_sync_call("provision credentials", NULL);

	iotivity_unlock();

	return 0;
}

static int run_ace2(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	StackmenuItem *ds, *dc;
	OCStackResult ret;
	OicSecAcl_t *acl;
	OicSecAce_t *ace;
	OicSecRsrc_t *rsrc;

	info("You should select 2 devices.");

	ds = _input_device_number(menu_owned, MSG_SELECT_SERVER);
	if (!ds) {
		info("Can't find device");
		return 0;
	}

	dc = _input_device_number(menu_owned, MSG_SELECT_CLIENT);
	if (!dc) {
		info("Can't find device");
		return 0;
	}

	acl = calloc(1, sizeof(OicSecAcl_t));
	if (!acl)
		return -1;

	ace = calloc(1, sizeof(OicSecAce_t));
	if (!ace) {
		free(acl);
		return -1;
	}

	LL_APPEND(acl->aces, ace);

	ace->subjectType = OicSecAceUuidSubject;
	ace->permission = PERMISSION_FULL_CONTROL;
	memcpy(&ace->subjectuuid,
			&((OCProvisionDev_t *)dc->custom_data)->doxm->deviceID,
			UUID_LENGTH);

	rsrc = calloc(1, sizeof(OicSecRsrc_t));
	if (!rsrc) {
		OCDeleteACLList(acl);
		return -1;
	}

	rsrc->href = strdup(data_acl_href);
	rsrc->typeLen = 1;
	rsrc->types = calloc(rsrc->typeLen, sizeof(char *));
	rsrc->types[0] = strdup(data_acl_rt);
	rsrc->interfaceLen = 2;
	rsrc->interfaces = calloc(rsrc->interfaceLen, sizeof(char *));
	rsrc->interfaces[0] = strdup("oic.if.baseline");
	rsrc->interfaces[1] = strdup(data_acl_if);
	LL_APPEND(ace->resources, rsrc);

	sync_call_done = 0;

	iotivity_lock();
	ret = OCProvisionACL2("Provision ACL2", ds->custom_data, acl,
			_provision_cb);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCProvisionACL2()", ret);
		iotivity_unlock();
		return -1;
	}
	iotivity_unlock();

	_wait_sync_call("provision acl", NULL);

	iotivity_unlock();

	OCDeleteACLList(acl);

	return 0;
}

static int run_unlink_pairwise(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	StackmenuItem *dev1, *dev2;
	OCStackResult ret;

	info("You should select 2 devices.");

	dev1 = _input_device_number(menu_owned,
			"Select target device-1 number");
	if (!dev1) {
		info("Can't find device");
		return 0;
	}

	dev2 = _input_device_number(menu_owned,
			"Select target device-2 number");
	if (!dev2) {
		info("Can't find device");
		return 0;
	}

	sync_call_done = 0;

	iotivity_lock();
	ret = OCUnlinkDevices("Unlink pairwise", dev1->custom_data,
			dev2->custom_data, _provision_cb);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCUnlinkDevices()", ret);
		iotivity_unlock();
		return -1;
	}
	iotivity_unlock();

	_wait_sync_call("unlink pairwise", NULL);

	iotivity_unlock();
	return 0;
}

static void _cd_destroy_cb(void *custom_data)
{
	OCDeleteDiscoveredDevices(custom_data);
}

static int run_discover_unowned(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	OCStackResult ret;
	OCProvisionDev_t *list = NULL, *tmp = NULL;
	char *id = NULL;
	int i;
	int key;
	StackmenuItem *item_unowned;

	if (iotivity_is_running() == 0) {
		info("onboarding client is not running.");
		return -1;
	}

	item_unowned = stackmenu_item_find(menu_obt_main, "3");
	if (!item_unowned) {
		error("stackmenu_item_find() failed.");
		return -1;
	}

	stackmenu_item_disable(item_unowned);

	for (i = 0; i < MENU_MAX_ITEMS; i++)
		stackmenu_item_clear(&menu_unowned[i]);

	info("Discover unowned devices during %d seconds", TIMEOUT_DISCOVER);

	iotivity_lock();
	ret = OCDiscoverUnownedDevices(TIMEOUT_DISCOVER, &tmp);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCDiscoverUnownedDevices()", ret);
		iotivity_unlock();
		return -1;
	}
	iotivity_unlock();

	if (!tmp) {
		info("No devices");
		return 0;
	}

	list = _get_device_list(tmp);
	OCDeleteDiscoveredDevices(tmp);
	if (!list) {
		info("No devices");
		return 0;
	}

	_dump_device_list(list);

	stackmenu_item_enable(item_unowned);

	i = 0;
	key = 0;
	for (tmp = list; tmp; tmp = tmp->next, key++, i++) {
		ConvertUuidToStr(&tmp->doxm->deviceID, &id);
		if (!id) {
			error("ConverUuidToStr() failed");
			continue;
		}

		menu_unowned[i].key = g_strdup_printf("%d", key);
		menu_unowned[i].title = g_strdup_printf("Take Ownership - %s",
				id);
		menu_unowned[i].custom_data = _clone_pdev(tmp);
		menu_unowned[i].custom_data_destroy_callback = _cd_destroy_cb;
		menu_unowned[i].callback = run_ownership;

		i++;
		menu_unowned[i].key = strdup("_");
		menu_unowned[i].title = g_strdup_printf("specVer: %s, addr: %s",
				tmp->specVer, tmp->endpoint.addr);

		if (tmp->next != NULL) {
			i++;
			menu_unowned[i].key = strdup("-");
			menu_unowned[i].title = NULL;
		}

		free(id);
		id = NULL;
	}

	OCDeleteDiscoveredDevices(list);

	return 0;
}

static int run_discover_owned(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	OCStackResult ret;
	OCProvisionDev_t *list = NULL, *tmp = NULL;
	char *id = NULL;
	int i;
	int key = 0;
	StackmenuItem *item_owned;

	if (iotivity_is_running() == 0) {
		info("onboarding client is not running.");
		return -1;
	}

	item_owned = stackmenu_item_find(menu_obt_main, "5");
	if (!item_owned) {
		error("stackmenu_item_find() failed.");
		return -1;
	}

	stackmenu_item_disable(item_owned);

	for (i = 0; i < MENU_MAX_ITEMS; i++)
		stackmenu_item_clear(&menu_owned[i]);

	info("Discover owned devices during %d seconds", TIMEOUT_DISCOVER);

	iotivity_lock();
	ret = OCDiscoverOwnedDevices(TIMEOUT_DISCOVER, &tmp);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCDiscoverOwnedDevices()", ret);
		iotivity_unlock();
		return -1;
	}
	iotivity_unlock();

	if (!tmp) {
		info("No devices");
		return 0;
	}

	list = _get_device_list(tmp);
	OCDeleteDiscoveredDevices(tmp);
	if (!list) {
		info("No devices");
		return 0;
	}

	_dump_device_list(list);

	stackmenu_item_enable(item_owned);

	for (tmp = list; tmp; tmp = tmp->next, key++) {
		ConvertUuidToStr(&tmp->doxm->deviceID, &id);
		if (!id) {
			error("ConverUuidToStr() failed");
			continue;
		}

		menu_owned[key].key = g_strdup_printf("^%d", key);
		menu_owned[key].title = g_strdup_printf("%s / %s", id,
				tmp->specVer);
		menu_owned[key].custom_data = _clone_pdev(tmp);
		menu_owned[key].custom_data_destroy_callback = _cd_destroy_cb;
		menu_owned[key].callback = NULL;

		free(id);
		id = NULL;
	}

	OCDeleteDiscoveredDevices(list);

	menu_owned[key].key = strdup("-");
	menu_owned[key].title = NULL;

	key++;
	if (key > 2)
		menu_owned[key].key = strdup("pc");
	else
		menu_owned[key].key = strdup("^pc");
	menu_owned[key].title = strdup("Pairwise Credentials");
	menu_owned[key].callback = run_cred;

	key++;
	if (key > 3)
		menu_owned[key].key = strdup("pa");
	else
		menu_owned[key].key = strdup("^pa");
	menu_owned[key].title = strdup("Pairwise ACE2");
	menu_owned[key].callback = run_ace2;

	key++;
	menu_owned[key].key = strdup("_");
	menu_owned[key].title = g_strdup_printf(
			"href: %s, rt: %s, perm: 31(ALL)", data_acl_href,
			data_acl_rt);
	key++;
	menu_owned[key].key = strdup("_");
	menu_owned[key].title = g_strdup_printf("if: [oic.if.baseline, %s]",
			data_acl_if);

	key++;
	menu_owned[key].key = strdup("-");
	menu_owned[key].title = NULL;

	key++;
	if (key > 7)
		menu_owned[key].key = strdup("up");
	else
		menu_owned[key].key = strdup("^up");
	menu_owned[key].title = strdup("Unlink pairwise");
	menu_owned[key].callback = run_unlink_pairwise;

	return 0;
}

static int run_reset_svr(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	if (iotivity_is_running()) {
		info("Please run before start onboarding client.");
		return 0;
	}

	if (unlink("svr_obt/provisioning.db") < 0) {
		if (errno != ENOENT) {
			error("unlink() failed");
			return -1;
		}
	}

	return svr_reset_obt("svr_obt/oic_svr_db.dat");
}

static int run_start_obt(Stackmenu *mm, StackmenuItem *menu,
		void *user_data)
{
	OCStackResult ret;
	OCResourceHandle device_h;

	if (iotivity_is_running()) {
		info("Onboarding client already started");
		return 0;
	}

	ret = OCInit(NULL, 0, OC_CLIENT_SERVER);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCInit()", ret);
		return -1;
	}

	ret = OCInitPM("svr_obt/provisioning.db");
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCInitPM()", ret);
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

	info("Onboarding client started.");

	run_update(NULL, NULL, NULL);
	info("UUID: %s", data_device_id);

	return 0;
}

static char key_unowned[3] = "^3";
static char key_owned[3] = "^5";

static StackmenuItem menu_obt_main[] = {
	DEFAULT_MENU,
	{ "0", "Reset SVR DB", NULL, run_reset_svr, NULL },
	{ "1", "Start onboarding client", NULL, run_start_obt, NULL },
	{ "-", NULL, },
	{ "*", " Discovery and Ownership Transfer" },
	{ "2", "Discover unowned devices", NULL, run_discover_unowned, NULL },
	{ key_unowned, "Unowned devices (Take Ownership)", menu_unowned, NULL, NULL },
	{ "-", NULL, },
	{ "*", " Control owned devices" },
	{ "4", "Discover owned devices", NULL, run_discover_owned, NULL },
	{ key_owned, "Owned devices", menu_owned, NULL, NULL },
	{ NULL, NULL, },
};

int main(int argc, char *argv[])
{
	GMainLoop *loop;
	Stackmenu *manager;

	loop = g_main_loop_new(NULL, FALSE);

	if (getenv("IOTIVITY_LOG_LEVEL") == NULL)
		setenv("IOTIVITY_LOG_LEVEL", "4", 1);

	info("\n Onboarding tool (Build with IoTivity v%s)", IOTIVITY_VERSION);

	iotivity_logsystem_syslog();
	security_init("svr_obt", CLIENT);

	manager = stackmenu_new(menu_obt_main, loop);
	stackmenu_run(manager);

	g_main_loop_run(loop);

	iotivity_stop();

	security_exit();

	info("bye bye");

	return 0;
}
