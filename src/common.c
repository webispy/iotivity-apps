#include "common.h"

#include <syslog.h>
#include <cainterface.h>
#include <pthread.h>
#include <oc_logger.h>
#include <experimental/logger.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t sync_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sync_cond = PTHREAD_COND_INITIALIZER;

static pthread_t tid;
static int running;

static void _rep(OCRepPayload *payload);

static void _tps_flags(OCTpsSchemeFlags flags)
{
	printf("- tps scheme flags: 0x%X ( ", flags);

	if (flags == OC_ALL) {
		printf("OC_ALL )\n");
		return;
	} else if (flags == OC_NO_TPS) {
		printf("OC_NO_TPS )\n");
		return;
	}

	if (flags & OC_COAP)
		printf("OC_COAP ");
	if (flags & OC_COAPS)
		printf("OC_COAPS ");

	printf(")\n");
}

static void _array_values(OCRepPayloadValue *val)
{
	size_t i;

	switch (val->arr.type) {
	case OCREP_PROP_INT:
		info("\t\t%s(int array):%" PRIuPTR " x %" PRIuPTR " x %" PRIuPTR ": ",
				val->name,
				val->arr.dimensions[0], val->arr.dimensions[1],
				val->arr.dimensions[2]);
		info("\t\t Values:");
		for (i = 0; i < val->arr.dimensions[0]; i++)
			info("\t\t\t %" PRId64, val->arr.iArray[i]);
		break;
	case OCREP_PROP_DOUBLE:
		info("\t\t%s(double array):%" PRIuPTR " x %" PRIuPTR " x %" PRIuPTR ": ",
				val->name,
				val->arr.dimensions[0], val->arr.dimensions[1],
				val->arr.dimensions[2]);
		info("\t\t Values:");
		for (i = 0; i < val->arr.dimensions[0]; i++)
			info("\t\t\t %lf", val->arr.dArray[i]);
		break;
	case OCREP_PROP_BOOL:
		info("\t\t%s(bool array):%" PRIuPTR " x %" PRIuPTR " x %" PRIuPTR ": ",
				val->name,
				val->arr.dimensions[0], val->arr.dimensions[1],
				val->arr.dimensions[2]);
		info("\t\t Values:");
		for (i = 0; i < val->arr.dimensions[0]; i++)
			info("\t\t\t %d", val->arr.bArray[i]);
		break;
	case OCREP_PROP_STRING:
		info("\t\t%s(string array):%" PRIuPTR " x %" PRIuPTR " x %" PRIuPTR ": ",
				val->name,
				val->arr.dimensions[0], val->arr.dimensions[1],
				val->arr.dimensions[2]);
		info("\t\t Values:");
		for (i = 0; i < val->arr.dimensions[0]; i++)
			info("\t\t\t %s", val->arr.strArray[i]);
		break;
	case OCREP_PROP_BYTE_STRING:
		info("\t\t%s(byte array):%" PRIuPTR " x %" PRIuPTR " x %" PRIuPTR ": ",
				val->name,
				val->arr.dimensions[0], val->arr.dimensions[1],
				val->arr.dimensions[2]);
		break;
	case OCREP_PROP_OBJECT:
		info("\t\t%s(object array):%" PRIuPTR " x %" PRIuPTR " x %" PRIuPTR ": ",
				val->name,
				val->arr.dimensions[0], val->arr.dimensions[1],
				val->arr.dimensions[2]);
		info("\t\t Values:");
		for (i = 0; i < val->arr.dimensions[0]; i++)
			_rep(val->arr.objArray[i]);
		break;
	case OCREP_PROP_ARRAY:
		/* Seems as nested arrays doesn't not supported in API */
	default:
		error("%s <-- Unknown/unsupported array type!", val->name);
		break;
	}
}

static void _values(OCRepPayloadValue *val)
{
	while (val) {
		switch (val->type) {
		case OCREP_PROP_NULL:
			info("\t\t%s: NULL", val->name);
			break;
		case OCREP_PROP_INT:
			info("\t\t%s(int): %" PRId64, val->name, val->i);
			break;
		case OCREP_PROP_DOUBLE:
			info("\t\t%s(double): %f", val->name, val->d);
			break;
		case OCREP_PROP_BOOL:
			info("\t\t%s(bool): %s", val->name, val->b ? "true" : "false");
			break;
		case OCREP_PROP_STRING:
			info("\t\t%s(string): %s", val->name, val->str);
			break;
		case OCREP_PROP_BYTE_STRING:
			info("\t\t%s(binary): ...", val->name);
			break;
		case OCREP_PROP_OBJECT:
			// Note: Only prints the URI (if available), to print further, you'll
			// need to dig into the object better!
			info("\t\t%s(object): ", val->name);
			_rep(val->obj);
			break;
		case OCREP_PROP_ARRAY:
			_array_values(val);
			break;
		default:
			error("%s <-- Unknown type!", val->name);
			break;
		}

		val = val-> next;
	}
}

void _rep(OCRepPayload *payload)
{
	uint32_t i = 1;
	OCRepPayload *rep = payload;
	OCStringLL *strll;

	info("Payload Type: Representation");

	for (; rep; rep = rep->next, ++i) {
		info("\tResource #%d", i);

		if (rep->uri)
			info("\tURI:%s", rep->uri);

		if (rep->types) {
			info("\tResource Types:");
			strll = rep->types;
			for (; strll; strll = strll->next)
				info("\t\t%s", strll->value);
		}

		if (rep->interfaces) {
			info("\tInterfaces:");
			strll = rep->interfaces;
			for (; strll; strll = strll->next)
				info("\t\t%s", strll->value);
		}

		info("\tValues:");
		_values(rep->values);
	}
}

static void _ll(OCStringLL *type)
{
	OCStringLL *strll = type;

	for (; strll; strll = strll->next)
		info("\t\t %s", strll->value);
}

static void _discovery(OCDiscoveryPayload *payload)
{
	OCResourcePayload *res;
	OCEndpointPayload *eps;
	uint32_t i, j;
	OCStringLL *strll;

	info("Payload Type: Discovery");

	while (payload && payload->resources) {
		info("\tDI: %s", payload->sid);
		if (payload->name)
			info("\tNAME: %s", payload->name);

		if (payload->type) {
			info("\tResource Type:");
			_ll(payload->type);
		}

		if (payload->iface) {
			info("\tInterface:");
			_ll(payload->iface);
		}

		i = 1;
		res = payload->resources;
		while (res) {
			info("\tLink#%d", i);
			info("\tURI:%s", res->uri);

			if (res->rel)
				info("\tRelation:%s", res->rel);

			if (res->anchor)
				info("\tAnchor:%s", res->anchor);

			info("\tResource Types:");
			strll = res->types;
			while (strll) {
				info("\t\t%s", strll->value);
				strll = strll->next;
			}

			info("\tInterfaces:");
			strll = res->interfaces;
			while (strll) {
				info("\t\t%s", strll->value);
				strll = strll->next;
			}

			info("\tBitmap: %u", res->bitmap);
			info("\tSecure?: %s", res->secure ? "true" : "false");
			info("\tPort: %u", res->port);

			j = 1;
			eps = res->eps;
			while (eps) {
				info("\tEndpoint #%d", j);
				info("\t\ttps: %s", eps->tps);
				info("\t\taddr: %s", eps->addr);
				info("\t\tport: %d", eps->port);
				info("\t\tpri: %d", eps->pri);
				eps = eps->next;
				++j;
			}

			info("");
			res = res->next;
			++i;
		}
		payload = payload->next;
	}
}

void iotivity_payload_dump(OCPayload *payload)
{
	if (!payload)
		return;

	switch (payload->type) {
	case PAYLOAD_TYPE_REPRESENTATION:
		_rep((OCRepPayload *)payload);
		break;
	case PAYLOAD_TYPE_DISCOVERY:
		_discovery((OCDiscoveryPayload *)payload);
		break;
	case PAYLOAD_TYPE_PRESENCE:
		info("Payload Type: Presence");
		break;
	case PAYLOAD_TYPE_SECURITY:
		info("Payload Type: Security");
		break;
	default:
		info("Unknown Payload Type: %d", payload->type);
		break;
	}
}

void iotivity_show_result(const char *msg, OCStackResult result)
{
	info("");

	switch (result) {
	case OC_STACK_OK:
		info("%s success(%d): OK (203 or 205)", msg, result);
		break;
	case OC_STACK_RESOURCE_CREATED:
		info("%s success(%d): Resource created (201)", msg, result);
		break;
	case OC_STACK_RESOURCE_DELETED:
		info("%s success(%d): Resource deleted (202)", msg, result);
		break;
	case OC_STACK_CONTINUE:
		info("%s success(%d): Continue", msg, result);
		break;
	case OC_STACK_RESOURCE_CHANGED:
		info("%s success(%d): Resource changed (204)", msg, result);
		break;
	case OC_STACK_INVALID_URI:
		info("%s failed(%d): Invalid URI", msg, result);
		break;
	case OC_STACK_INVALID_QUERY:
		info("%s failed(%d): Invalid query (400)", msg, result);
		break;
	case OC_STACK_INVALID_IP:
		info("%s failed(%d): Invalid IP", msg, result);
		break;
	case OC_STACK_INVALID_PORT:
		info("%s failed(%d): Invalid port", msg, result);
		break;
	case OC_STACK_INVALID_CALLBACK:
		info("%s failed(%d): Invalid callback", msg, result);
		break;
	case OC_STACK_INVALID_METHOD:
		info("%s failed(%d): Invalid method (405)", msg, result);
		break;
	case OC_STACK_INVALID_PARAM:
		info("%s failed(%d): Invalid param", msg, result);
		break;
	case OC_STACK_INVALID_OBSERVE_PARAM:
		info("%s failed(%d): Invalid observe param", msg, result);
		break;
	case OC_STACK_NO_MEMORY:
		info("%s failed(%d): no memory", msg, result);
		break;
	case OC_STACK_COMM_ERROR:
		info("%s failed(%d): Comm error (504)", msg, result);
		break;
	case OC_STACK_TIMEOUT:
		info("%s failed(%d): Timeout", msg, result);
		break;
	case OC_STACK_ADAPTER_NOT_ENABLED:
		info("%s failed(%d): Adapter not enabled", msg, result);
		break;
	case OC_STACK_NOTIMPL:
		info("%s failed(%d): Not implement", msg, result);
		break;
	case OC_STACK_NO_RESOURCE:
		info("%s failed(%d): No resource (404)", msg, result);
		break;
	case OC_STACK_UNAUTHORIZED_REQ:
		info("%s failed(%d): Unauthorized request (401)", msg, result);
		break;
	case OC_STACK_TOO_LARGE_REQ:
		info("%s failed(%d): Too large request (413)", msg, result);
		break;
	case OC_STACK_PDM_IS_NOT_INITIALIZED:
		info("%s failed(%d): PMD is not initialized", msg, result);
		break;
	case OC_STACK_DUPLICATE_UUID:
		info("%s failed(%d): Duplicated UUID", msg, result);
		break;
	case OC_STACK_INCONSISTENT_DB:
		info("%s failed(%d): Inconsistent DB", msg, result);
		break;
	case OC_STACK_AUTHENTICATION_FAILURE:
		info("%s failed(%d): Authentication failure", msg, result);
		break;
	case OC_STACK_NOT_ALLOWED_OXM:
		info("%s failed(%d): Not allowed OXM", msg, result);
		break;
	case OC_STACK_CONTINUE_OPERATION:
		info("%s failed(%d): Continue operation", msg, result);
		break;
	case OC_STACK_BAD_ENDPOINT:
		info("%s failed(%d): Bad endpoint", msg, result);
		break;
	case OC_STACK_USER_DENIED_REQ:
		info("%s failed(%d): User denied request", msg, result);
		break;
	case OC_STACK_NOT_ACCEPTABLE:
		info("%s failed(%d): Not acceptable (406)", msg, result);
		break;
	case OC_STACK_FORBIDDEN_REQ:
		info("%s failed(%d): Forbidden request (403)", msg, result);
		break;
	case OC_STACK_INTERNAL_SERVER_ERROR:
		info("%s failed(%d): Internal server error (500)", msg, result);
		break;
	case OC_STACK_GATEWAY_TIMEOUT:
		info("%s failed(%d): Gateway timeout (504)", msg, result);
		break;
	case OC_STACK_SERVICE_UNAVAILABLE:
		info("%s failed(%d): Service unavailable (503)", msg, result);
		break;
	case OC_STACK_ERROR:
		info("%s failed(%d): Error", msg, result);
		break;
	default:
		info("%s failed(%d)", msg, result);
		break;
	}
}

void iotivity_show_flags(const char *msg, OCTransportFlags flags,
		const char *msg_last)
{
	printf("%sFlags: 0x%X ( ", msg, flags);

	if (flags & OC_FLAG_SECURE)
		printf("SECURE ");
	if (flags & OC_IP_USE_V6)
		printf("IPv6 ");
	if (flags & OC_IP_USE_V4)
		printf("IPv4 ");
	if (flags & OC_MULTICAST)
		printf("MULTICAST ");

	if (flags == OC_DEFAULT_FLAGS)
		printf("DEFAULT");

	if ((flags & OC_MASK_SCOPE) == OC_SCOPE_INTERFACE)
		printf("SCOPE_INTERFACE ");

	if ((flags & OC_MASK_SCOPE) == OC_SCOPE_LINK)
		printf("SCOPE_LINK ");

	if ((flags & OC_MASK_SCOPE) == OC_SCOPE_REALM)
		printf("SCOPE_REALM ");

	if ((flags & OC_MASK_SCOPE) == OC_SCOPE_SITE)
		printf("SCOPE_SITE ");

	if ((flags & OC_MASK_SCOPE) == OC_SCOPE_ORG)
		printf("SCOPE_ORG ");

	if ((flags & OC_MASK_SCOPE) == OC_SCOPE_GLOBAL)
		printf("SCOPE_GLOBAL ");

	if (!msg_last)
		printf(")\n");
	else
		printf(")%s", msg_last);
}

void iotivity_show_adapter(const char *msg, OCTransportAdapter adapter,
		const char *msg_last)
{
	printf("%sAdapter: 0x%X ( ", msg, adapter);

	if (adapter & OC_ADAPTER_IP)
		printf("IP ");
	if (adapter & OC_ADAPTER_GATT_BTLE)
		printf("BTLE ");
	if (adapter & OC_ADAPTER_RFCOMM_BTEDR)
		printf("BTEDR ");
	if (adapter & OC_ADAPTER_TCP)
		printf("TCP ");
	if (adapter & OC_ADAPTER_NFC)
		printf("NFC ");

	if (adapter == OC_DEFAULT_ADAPTER)
		printf("DEFAULT");

	if (!msg_last)
		printf(")\n");
	else
		printf(")%s", msg_last);
}

void iotivity_show_connectivity_type(const char *msg, OCConnectivityType type,
		const char *msg_last)
{
	printf("%sConnectivity Type: 0x%X ( ", msg, type);

	if (type & CT_ADAPTER_IP)
		printf("IP ");
	if (type & CT_ADAPTER_GATT_BTLE)
		printf("BTLE ");
	if (type & CT_ADAPTER_RFCOMM_BTEDR)
		printf("BTEDR ");
	if (type & CT_ADAPTER_TCP)
		printf("TCP ");
	if (type & CT_ADAPTER_NFC)
		printf("NFC ");
	if (type & CT_FLAG_SECURE)
		printf("SECURE ");
	if (type & CT_IP_USE_V6)
		printf("IPv6 ");
	if (type & CT_IP_USE_V4)
		printf("IPv4 ");

	if (type == CT_DEFAULT)
		printf("DEFAULT");

	if (!msg_last)
		printf(")\n");
	else
		printf(")%s", msg_last);
}

void iotivity_show_addr(const char *msg, OCDevAddr *addr)
{
	printf("%s to %s:%d\n", msg, addr->addr, addr->port);
	iotivity_show_flags("  - ", addr->flags, NULL);
}

static void *loop_iotivity(void *data)
{
	OCStackResult ret;
	struct timespec timeout;

	g_atomic_int_set(&running, 1);

	pthread_mutex_lock(&sync_mutex);
	pthread_cond_signal(&sync_cond);
	pthread_mutex_unlock(&sync_mutex);

	timeout.tv_sec = 0;
	timeout.tv_nsec = 100000000L; /* 0.1 sec */

	while (g_atomic_int_get(&running)) {
		pthread_mutex_lock(&lock);
		ret = OCProcess();
		pthread_mutex_unlock(&lock);
		if (ret != OC_STACK_OK) {
			iotivity_show_result("OCProcess()", ret);
			break;
		}

		nanosleep(&timeout, NULL);
	}

	return NULL;
}

static void _ca_info(void)
{
	CAEndpoint_t *ninfo = NULL;
	size_t i, nsize = 0;
	CAResult_t ret;

	ret = CAGetNetworkInformation(&ninfo, &nsize);
	if (ret != CA_STATUS_OK) {
		error("CAGetNEtworkInformation() failed(%d)", ret);
		return;
	}

	printf("- networks: %zd\n", nsize);
	for (i = 0; i < nsize; i++) {
		printf("  [%2zd] %s:%d\n", i, ninfo[i].addr, ninfo[i].port);
		iotivity_show_adapter("       ", ninfo[i].adapter, ", ");
		iotivity_show_flags("", ninfo[i].flags, NULL);
	}

	if (ninfo)
		free(ninfo);
}

static const char *_level_str[] = {
	"ALL  ",
	"FATAL",
	"ERROR",
	"WARN ",
	"INFO ",
	"DEBUG",
	"     "
};

static int _syslog_level[] = {
	LOG_DEBUG, /* OC_LOG_ALL */
	LOG_CRIT, /* OC_LOG_FATAL */
	LOG_ERR, /* OC_LOG_ERROR */
	LOG_WARNING, /* OC_LOG_WARNING */
	LOG_INFO, /* OC_LOG_INFO */
	LOG_DEBUG, /* OC_LOG_DEBUG */
	LOG_DEBUG /* OC_LOG_DISABLED */
};

static size_t on_write_tag_level(oc_log_ctx_t *ctx, int level, const char *tag,
		const char *msg)
{
	syslog(_syslog_level[level], "%s: %s: %s", _level_str[level], tag, msg);

	return 0;
}

static oc_log_ctx_t log_ctx = {
	.ctx = "MyLog",
	.log_level = OC_LOG_ALL,
	.module_name = "mymodule",
	.write_tag_level = on_write_tag_level,
};

void iotivity_logsystem_syslog(void)
{
	OCLogConfig(&log_ctx);
}

void iotivity_logsystem_stdout(void)
{
	OCLogConfig(NULL);
}

int iotivity_start(void)
{
	bool is_owned = FALSE;
	OCStackResult ret;

	if (g_atomic_int_get(&running) == 1) {
		dbg("iotivity already running");
		return 0;
	}

	pthread_mutex_init(&sync_mutex, NULL);
	pthread_cond_init(&sync_cond, NULL);

	pthread_mutex_lock(&sync_mutex);
	if (pthread_create(&tid, NULL, loop_iotivity, NULL) != 0) {
		pthread_mutex_unlock(&sync_mutex);
		error("pthread_create() failed");
		return -1;
	}
	pthread_cond_wait(&sync_cond, &sync_mutex);
	pthread_mutex_unlock(&sync_mutex);

	_tps_flags(OCGetSupportedEndpointTpsFlags());

	_ca_info();

	ret = OCGetDeviceOwnedState(&is_owned);
	if (ret != OC_STACK_OK) {
		iotivity_show_result("OCGetDeviceOwnedState()", ret);
		return 0;
	}

	printf("- device owned: %d\n", is_owned);

	return 0;
}

int iotivity_stop(void)
{
	OCStackResult ret;

	if (g_atomic_int_get(&running) == 0)
		return 0;

	g_atomic_int_set(&running, 0);
	pthread_join(tid, NULL);

	ret = OCStop();
	if (ret != OC_STACK_OK) {
		error("OCStop() failed(%d)", ret);
		return -1;
	}

	return 0;
}

int iotivity_is_running(void)
{
	return g_atomic_int_get(&running);
}

int iotivity_lock(void)
{
	return pthread_mutex_lock(&lock);
}

int iotivity_unlock(void)
{
	return pthread_mutex_unlock(&lock);
}

int iotivity_get_uuid(char *out, size_t out_len)
{
	OicUuid_t uuid;
	OCStackResult ret;
	char *id = NULL;

	if (!out)
		return -1;

	memset(&uuid, 0, sizeof(OicUuid_t));
	ret = GetDoxmDeviceID(&uuid);
	if (ret != OC_STACK_OK) {
		error("GetDoxmDeviceID() failed(%d)", ret);
		return -1;
	}

	ret = ConvertUuidToStr(&uuid, &id);
	if (ret != OC_STACK_OK) {
		error("ConvertUuidToStr() failed(%d)", ret);
		return -1;
	}

	if (!id)
		return -1;

	strncpy(out, id, out_len);
	free(id);

	return 0;
}
