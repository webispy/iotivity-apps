#ifndef __IOTIVITY_APPS_SECURITY_H__
#define __IOTIVITY_APPS_SECURITY_H__

enum device_role {
	SERVER,
	CLIENT
};

int security_init(const char *path, enum device_role role);
void security_exit(void);

#endif
