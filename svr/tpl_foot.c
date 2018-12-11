
static int _save_cbor(unsigned char *data, unsigned int len,
		const char *path)
{
	FILE *fp;
	size_t nwrite;

	fp = fopen(path, "w");
	if (!fp) {
		fprintf(stderr, "fopen(%s) failed.\n", path);
		return -1;
	}

	nwrite = fwrite(data, 1, len, fp);
	if (nwrite != len) {
		fprintf(stderr, "fwrite() result %zd mismatch with %u\n",
				nwrite, len);
		fclose(fp);
		return -1;
	}

	fclose(fp);

	return 0;
}

int svr_reset_server(const char *path)
{
	return _save_cbor(server_svr_db_dat, server_svr_db_dat_len,
			path);
}

int svr_reset_client(const char *path)
{
	return _save_cbor(client_svr_db_dat, client_svr_db_dat_len,
			path);
}

int svr_reset_obt(const char *path)
{
	return _save_cbor(obt_svr_db_dat, obt_svr_db_dat_len,
			path);
}

