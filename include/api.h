#ifndef SERVER_KEY_MANAGEMENT_PLUGIN_API_H
#define SERVER_KEY_MANAGEMENT_PLUGIN_API_H

#include "hv/hlog.h"

unsigned int init_client(const char* ca_path, const char* ca_file, const char* crt_file, const char* key_file);
unsigned int del_client();

#endif