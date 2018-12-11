#ifndef __IOTIVITY_APPS_CRUDN_H__
#define __IOTIVITY_APPS_CRUDN_H__

struct crudn_ops {
	OCEntityHandler get;
	OCEntityHandler put;
	OCEntityHandler post;
	OCEntityHandler del;
	OCEntityHandler register_observe;
	OCEntityHandler deregister_observe;
};

struct crudn_dev_ops {
	OCDeviceEntityHandler get;
	OCDeviceEntityHandler put;
	OCDeviceEntityHandler post;
	OCDeviceEntityHandler del;
};

OCEntityHandlerResult crudn_handler(OCEntityHandlerFlag flag,
		OCEntityHandlerRequest *req, void *user_data);
OCEntityHandlerResult crudn_dev_handler(OCEntityHandlerFlag flag,
		OCEntityHandlerRequest *req, char *uri, void *user_data);

#endif
