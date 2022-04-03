#include "api.h"
#include <string.h>
#include "hv/http_client.h"
typedef unsigned int uint;
using namespace hv;
#define ERR_WRONG_PARAM -1
#define ERR_UNEXPECTED -500



/*
    Underlying Support Functions
*/

uint call_api() {
    // TODO 设计实现
}

static http_client_t *cli = NULL; // 客户端

uint init_client(const char* ca_path, const char* ca_file, const char* crt_file, const char* key_file) {
    // 创建Client
    cli = http_client_new(NULL, 7709, 1);
    if(cli == NULL) {
        hloge("Error: http_client_new got null\n");
        return ERR_UNEXPECTED;
    }

    // 设置证书
    hssl_ctx_opt_t ssl_opt;
    ssl_opt.verify_peer = 1;
    ssl_opt.endpoint = HSSL_CLIENT;
    ssl_opt.ca_path = format_path(ca_path);
    ssl_opt.ca_file = format_path(ca_file);
    ssl_opt.crt_file = format_path(crt_file);
    ssl_opt.key_file = format_path(key_file);
    int ret = http_client_new_ssl_ctx(cli, &ssl_opt);
    if(ret != 0) {
        hloge("Cert Error: %s : %d\n", http_client_strerror(ret), ret);
        return ret;
    }
    return 0;
}

uint del_client() {
    if(cli != NULL)
        http_client_del(cli);
}

const char *format_path(const char* path) {
    if(!path || !*path || strlen(path) == 0)
        return NULL;
    return path;
}

uint send_request(HttpRequest* req, HttpResponse* resp) {
    if(req == NULL || resp == NULL)
        return ERR_WRONG_PARAM;
    return http_client_send(cli, req, resp);
}