int parse_http_request(register struct kevent *kephttp, char *);
int get_response(char *bufout, register struct kevent *kephttp, int page_is_read);
