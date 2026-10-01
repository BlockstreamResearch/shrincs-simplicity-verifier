// gen.cpp — generate SHRINCS-L test vectors (stateful for every q, plus a few stateless) as JSON lines.
#include "shrincs.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

using namespace Parameters;
using namespace SHRINCS;

static std::string hex(const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(2 * n);
    for (size_t i = 0; i < n; i++) { s.push_back(d[p[i] >> 4]); s.push_back(d[p[i] & 15]); }
    return s;
}

int main(int argc, char** argv) {
    int n_stateful = argc > 1 ? atoi(argv[1]) : 10;
    int n_stateless = argc > 2 ? atoi(argv[2]) : 2;
    const char* out_path = argc > 3 ? argv[3] : "vectors.jsonl";
    FILE* out = fopen(out_path, "w");

    PublicKey pk; SecretKey sk; State state;
    shrincs_key_gen(pk, sk, state);
    fprintf(out, "{\"kind\":\"key\",\"seed\":\"%s\",\"root\":\"%s\",\"sf\":\"%s\",\"sl\":\"%s\"}\n",
            hex(pk.seed.data(), N).c_str(), hex(pk.root.data(), N).c_str(), hex(sk.sf.data(), N).c_str(), hex(sk.sl.data(), N).c_str());
    fflush(out);

    unsigned char message[32];
    for (int i = 0; i < n_stateful; i++) {
        for (int j = 0; j < 32; j++) message[j] = (unsigned char)((i * 131 + j * 17 + 7) & 0xff);
        uint32_t q = state.q + 1;
        unsigned char* sig = shrincs_sign_stateful(message, sk, state);
        uint32_t path_nodes = q > HSF ? HSF : q;
        uint32_t sig_len = N + WOTS_SIGN_LEN + path_nodes * N;
        bool ok = shrincs_verify_stateful(message, sig, sig_len, pk);
        fprintf(out, "{\"kind\":\"stateful\",\"q\":%u,\"message\":\"%s\",\"sig\":\"%s\",\"cpp_verify\":%s}\n",
                q, hex(message, 32).c_str(), hex(sig, sig_len).c_str(), ok ? "true" : "false");
        fflush(out);
        delete[] sig;
        fprintf(stderr, "stateful q=%u done (%s)\n", q, ok ? "ok" : "FAIL");
    }
    for (int i = 0; i < n_stateless; i++) {
        for (int j = 0; j < 32; j++) message[j] = (unsigned char)((i * 97 + j * 31 + 3) & 0xff);
        unsigned char* sig = shrincs_sign_stateless(message, sk);
        bool ok = shrincs_verify_stateless(message, sig, pk);
        fprintf(out, "{\"kind\":\"stateless\",\"message\":\"%s\",\"sig\":\"%s\",\"cpp_verify\":%s}\n",
                hex(message, 32).c_str(), hex(sig, SL_SIZE).c_str(), ok ? "true" : "false");
        fflush(out);
        delete[] sig;
        fprintf(stderr, "stateless %d done (%s)\n", i, ok ? "ok" : "FAIL");
    }
    fclose(out);
    return 0;
}
