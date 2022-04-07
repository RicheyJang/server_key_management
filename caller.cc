#include "api.h"
#include <string.h>
#include <sstream>
#include "hv/http_client.h"
using namespace hv;

#define ERR_UNEXPECTED 20000
#define ERR_WRONG_PARAM 20001
#define ERR_KEY_INVALID 20002
#define ERR_JSON_INVALID 20003


uint from_server_get_key_info(uint key_id, uint key_version, key_info_t *key) {
    std::stringstream ss;
    ss<<"{\"id\": "<<key_id<<", \"version\": "<<key_version<<"}";
    return call_key_api("api/inner/key", ss.str(), key);
}

uint from_server_get_latest_version_key(uint key_id, key_info_t *key) {
    std::stringstream ss;
    ss<<"{\"id\": "<<key_id<<"}";
    return call_key_api("api/inner/version", ss.str(), key);
}

/*
    Underlying Support Functions
*/

static http_client_t *cli = NULL; // 客户端
extern char* url_of_server;

void to_json(nlohmann::json& j, const key_info_t& k) {
    j = Json{};
}

unsigned char from_hex(char c) {
    if(c>='0' && c<='9')
        return c-'0';
    if(c>='a' && c<='f')
        return 10+(c-'a');
    if(c>='A' && c<='F')
        return 10+(c-'A');
    return 0;
}

void from_json(const nlohmann::json& j, key_info_t& k) {
    j.at("id").get_to(k.id);
    j.at("version").get_to(k.version);
    std::string hex;
    j.at("key").get_to(hex);
    // 将hex转换为k.key
    for(uint i=0,j=0;j<MAX_KEY_LENGTH && i+1<hex.length();i+=2,j++) {
        k.key[j]=from_hex(hex[i])*16+from_hex(hex[i+1]);
    }
    j.at("length").get_to(k.length);
    j.at("algorithm").get_to(k.algorithm);
    j.at("timeout").get_to(k.timeout);
}

int send_request(HttpRequest* req, HttpResponse* resp) {
    if(req == NULL || resp == NULL)
        return ERR_WRONG_PARAM;
    return http_client_send(cli, req, resp);
}

uint call_key_api(std::string path, std::string body, key_info_t *key) {
    if(key == NULL) {
        hloge("call_key_api: key is null");
        return ERR_WRONG_PARAM;
    }
    // 创建请求
    HttpRequest req;
    req.method = HTTP_POST;
    if(path.length() == 0 || path[0] != '/')
        path = '/' + path;
    req.url = std::string("https://")+std::string(url_of_server)+path;
    req.headers["Connection"] = "keep-alive";
    req.headers["Content-Type"] = "application/json; charset=utf-8";
    req.headers["user-agent"] = "server_key_manangement plugin v1.0";
    req.body = body;
    req.timeout = 10;

    // 发送请求
    HttpResponse resp;
    int ret = send_request(&req, &resp);
    if(ret != 0) {
        hloge("call_key_api: send_request failed: %d | %s", ret, http_client_strerror(ret));
        return ret < 0? -ret : ret;
    }

    // 解析
    try {
        Json rsp = Json::parse(resp.Body());
        ret = rsp.at("code").get<int>();
        if(ret != 0) {
            hloge("Error From Server: %d : %s", ret, rsp.at("msg").get<std::string>().c_str());
            return ret < 0? -ret : ret;
        }
        *key = rsp.at("key").get<key_info_t>();
    } catch(...) {
        hloge("call_key_api: parse json failed");
        return ERR_JSON_INVALID;
    }
    if(!key->check_key_valid()) {
        hloge("call_key_api: got invalid key");
        return ERR_KEY_INVALID;
    }
    return 0;
}

const char *format_path(const char* path) {
    if(!path || !*path || strlen(path) == 0)
        return NULL;
    return path;
}

uint init_client(const char* ca_path, const char* ca_file, const char* crt_file, const char* key_file) {
    // 创建Client
    cli = http_client_new(NULL, 7709, 1);
    if(cli == NULL) {
        hloge("init_client: http_client_new got null");
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
    if(ssl_opt.crt_file == NULL || ssl_opt.key_file == NULL) {
        hlogw("init_client: The Path of Cert or Key File has not yet been set.");
        return ERR_WRONG_PARAM;
    }
    int ret = http_client_new_ssl_ctx(cli, &ssl_opt);
    if(ret != 0) {
        hloge("init_client: Cert Error: %d : %s", ret, http_client_strerror(ret));
        return ret < 0? -ret : ret;
    }
    return 0;
}

uint del_client() {
    if(cli != NULL)
        http_client_del(cli);
    return 0;
}
