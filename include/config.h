#define MAXVARNAME  25

configD configVar[] = {
	{ 0, "logfile", STRING, 0, 0 },
	{ 1, "http_host", STRING, 0, 0 },
	{ 2, "http_port", DIGIT, 0, 0 },
	{ 3, "system_host", STRING, 0, 0 },
	{ 4, "system_port", DIGIT, 0, 0 },
	{ 5, "daemon_uid", STRING, 0, 0 },
	{ 6, "daemon_gid", STRING, 0, 0 },
	{ 7, "accesslog", STRING, 0, 0 },
	{ 8, "template_path", STRING, 0, 0 },
	{ 9, "template_in_memory", DIGIT, 0, 0 },
	{ 10, "is_daemon", DIGIT, 0, 0 },
	{ 11, "scan_network", DIGIT, 0, 0 },
	{ 12, "sys_user", STRING, 0, 0 },
	{ 13, "sys_password", STRING, 0, 0 },
};
