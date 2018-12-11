#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "common.h"
#include "crudn.h"

OCEntityHandlerResult crudn_handler(OCEntityHandlerFlag flag,
		OCEntityHandlerRequest *req, void *user_data)
{
	struct crudn_ops *ops = user_data;
	OCEntityHandlerResult ret = OC_EH_METHOD_NOT_ALLOWED;

	if (!ops)
		return ret;

	if (flag & OC_REQUEST_FLAG) {
		if (req->method == OC_REST_GET && ops->get)
			ret = ops->get(flag, req, user_data);
		else if (req->method == OC_REST_PUT && ops->put)
			ret = ops->put(flag, req, user_data);
		else if (req->method == OC_REST_POST && ops->post)
			ret = ops->post(flag, req, user_data);
		else if (req->method == OC_REST_DELETE && ops->del)
			ret = ops->del(flag, req, user_data);
	}

	if (flag & OC_OBSERVE_FLAG) {
		if (req->obsInfo.action == OC_OBSERVE_REGISTER
				&& ops->register_observe)
			ret = ops->register_observe(flag, req, user_data);
		else if (req->obsInfo.action == OC_OBSERVE_DEREGISTER
				&& ops->deregister_observe)
			ret = ops->deregister_observe(flag, req, user_data);
	}

	return ret;
}

OCEntityHandlerResult crudn_dev_handler(OCEntityHandlerFlag flag,
		OCEntityHandlerRequest *req, char *uri, void *user_data)
{
	struct crudn_dev_ops *ops = user_data;
	OCEntityHandlerResult ret = OC_EH_METHOD_NOT_ALLOWED;

	if (!ops)
		return ret;

	if (uri) {
		if (strcmp(uri, "/oic/d") != 0)
			return OC_EH_RESOURCE_NOT_FOUND;
	}

	if (flag & OC_REQUEST_FLAG) {
		if (req->method == OC_REST_GET && ops->get)
			ret = ops->get(flag, req, uri, user_data);
		else if (req->method == OC_REST_PUT && ops->put)
			ret = ops->put(flag, req, uri, user_data);
		else if (req->method == OC_REST_DELETE && ops->del)
			ret = ops->del(flag, req, uri, user_data);
	}

	return ret;
}

