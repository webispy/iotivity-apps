#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "common.h"
#include "security.h"

static char *db_path;

static FILE *on_open(const char *path, const char *mode)
{
	FILE *fp;
	char tmp[4096];

	if (!path)
		return NULL;

	snprintf(tmp, 4096, "%s/%s", db_path, path);
	fp = fopen(tmp, mode);
	if (!fp) {
		/* Skip error message for device_properties.dat */
		if (!g_strcmp0(path, "device_properties.dat"))
			return NULL;

		error("fopen() failed. path=%s, mode=%s", tmp, mode);
		return NULL;
	}

	return fp;
}

static OCPersistentStorage ps = {
	.open = on_open,
	.read = fread,
	.write = fwrite,
	.close = fclose,
	.unlink = unlink
};

int security_init(const char *path, enum device_role role)
{
	struct stat statinfo;
	char tmp[4096];

	if (!path)
		return -1;

	if (stat(path, &statinfo) < 0) {
		if (mkdir(path, 0755) < 0)
			return -1;
	}


	snprintf(tmp, 4096, "%s/oic_svr_db.dat", path);

	if (stat(tmp, &statinfo) < 0) {
		if (role == SERVER)
			svr_reset_server(tmp);
		else if (role == CLIENT)
			svr_reset_client(tmp);
	}

	db_path = strdup(path);

	OCRegisterPersistentStorageHandler(&ps);

	return 0;
}

void security_exit(void)
{
	if (!db_path)
		return;

	free(db_path);
	db_path = NULL;
}
