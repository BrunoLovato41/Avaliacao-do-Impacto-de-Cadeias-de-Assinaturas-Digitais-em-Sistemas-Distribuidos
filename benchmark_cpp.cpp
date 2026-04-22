#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <chrono>
#include <numeric>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// =============================================================================
// CONFIGURACAO
// =============================================================================

static const std::vector<int> PAYLOAD_SIZES   = {8, 16, 32, 64, 128, 256, 512, 1024};
static const std::vector<int> PROCESS_COUNTS  = {1, 2, 3, 4, 5, 6, 7, 8};
static const int               REPETITIONS    = 30;
static const double            CI_Z           = 1.96;

static const std::vector<std::string> SIG_ALGORITHMS  = {"RSA", "Ed25519"};
static const std::vector<std::string> CONF_ALGORITHMS = {"None", "AES-GCM", "ChaCha20-Poly1305"};

static const int RSA_KEY_BITS    = 2048;
static const int AES_KEY_BYTES   = 32;   // AES-256
static const int CHACHA_KEY_BYTES = 32;
static const int NONCE_BYTES     = 12;
static const int TAG_BYTES       = 16;


// =============================================================================
// UTILITARIOS
// =============================================================================

static void check_openssl(int rc, const char* msg) {
    if (rc <= 0) {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        throw std::runtime_error(std::string(msg) + ": " + buf);
    }
}

static int64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
}

static std::vector<uint8_t> random_bytes(int n) {
    std::vector<uint8_t> buf(n);
    RAND_bytes(buf.data(), n);
    return buf;
}


// =============================================================================
// 1. CHAVES
// =============================================================================

struct KeyPair {
    EVP_PKEY* pkey = nullptr;
    ~KeyPair() { if (pkey) EVP_PKEY_free(pkey); }
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;
    KeyPair() = default;
    KeyPair(KeyPair&& o) : pkey(o.pkey) { o.pkey = nullptr; }
    KeyPair& operator=(KeyPair&& o) {
        if (this != &o) {
            if (pkey) EVP_PKEY_free(pkey);
            pkey = o.pkey;
            o.pkey = nullptr;
        }
        return *this;
    }
};

KeyPair generate_rsa_keypair() {
    KeyPair kp;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS);
    EVP_PKEY_keygen(ctx, &kp.pkey);
    EVP_PKEY_CTX_free(ctx);
    return kp;
}

KeyPair generate_ed25519_keypair() {
    KeyPair kp;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &kp.pkey);
    EVP_PKEY_CTX_free(ctx);
    return kp;
}


// =============================================================================
// 2. ASSINATURA
// =============================================================================

std::vector<uint8_t> do_sign(EVP_PKEY* priv,
                              const std::vector<uint8_t>& data,
                              const std::string& algo) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = (algo == "RSA") ? EVP_sha256() : nullptr;

    // Para Ed25519 o digest é interno — passa nullptr
    EVP_PKEY_CTX* pctx = nullptr;
    check_openssl(EVP_DigestSignInit(ctx, &pctx, md, nullptr, priv), "DigestSignInit");
    if (algo == "RSA") {
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_MAX_SIGN);
    }

    if (algo == "RSA") {
        check_openssl(EVP_DigestSignUpdate(ctx, data.data(), data.size()), "DigestSignUpdate");
        size_t siglen = 0;
        check_openssl(EVP_DigestSignFinal(ctx, nullptr, &siglen), "DigestSignFinal(len)");
        std::vector<uint8_t> sig(siglen);
        check_openssl(EVP_DigestSignFinal(ctx, sig.data(), &siglen), "DigestSignFinal");
        sig.resize(siglen);
        EVP_MD_CTX_free(ctx);
        return sig;
    } else {
        // Ed25519: one-shot
        size_t siglen = 0;
        check_openssl(EVP_DigestSign(ctx, nullptr, &siglen, data.data(), data.size()), "DigestSign(len)");
        std::vector<uint8_t> sig(siglen);
        check_openssl(EVP_DigestSign(ctx, sig.data(), &siglen, data.data(), data.size()), "DigestSign");
        sig.resize(siglen);
        EVP_MD_CTX_free(ctx);
        return sig;
    }
}

void do_verify(EVP_PKEY* pub,
               const std::vector<uint8_t>& data,
               const std::vector<uint8_t>& sig,
               const std::string& algo) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = (algo == "RSA") ? EVP_sha256() : nullptr;

    EVP_PKEY_CTX* pctx = nullptr;
    check_openssl(EVP_DigestVerifyInit(ctx, &pctx, md, nullptr, pub), "DigestVerifyInit");
    if (algo == "RSA") {
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_AUTO);
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    }

    int rc;
    if (algo == "RSA") {
        check_openssl(EVP_DigestVerifyUpdate(ctx, data.data(), data.size()), "DigestVerifyUpdate");
        rc = EVP_DigestVerifyFinal(ctx, sig.data(), sig.size());
    } else {
        rc = EVP_DigestVerify(ctx, sig.data(), sig.size(), data.data(), data.size());
    }
    EVP_MD_CTX_free(ctx);
    check_openssl(rc, "DigestVerify");
}


// =============================================================================
// 3. CONFIDENCIALIDADE  (AEAD: AES-256-GCM e ChaCha20-Poly1305)
// =============================================================================

// Retorna nonce(12) + ciphertext + tag(16)
std::vector<uint8_t> aead_encrypt(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& pt,
                                   const std::string& algo) {
    const EVP_CIPHER* cipher = (algo == "AES-GCM")
        ? EVP_aes_256_gcm()
        : EVP_chacha20_poly1305();

    std::vector<uint8_t> nonce = random_bytes(NONCE_BYTES);
    std::vector<uint8_t> ct(pt.size() + TAG_BYTES);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    check_openssl(EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr), "EncInit");
    check_openssl(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_BYTES, nullptr), "SetIVLen");
    check_openssl(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()), "EncInit2");

    int outl = 0, totl = 0;
    check_openssl(EVP_EncryptUpdate(ctx, ct.data(), &outl, pt.data(), (int)pt.size()), "EncUpdate");
    totl = outl;
    check_openssl(EVP_EncryptFinal_ex(ctx, ct.data() + totl, &outl), "EncFinal");
    totl += outl;
    check_openssl(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_BYTES, ct.data() + totl), "GetTag");
    EVP_CIPHER_CTX_free(ctx);

    ct.resize(totl + TAG_BYTES);

    // Formato final: nonce | ciphertext | tag
    std::vector<uint8_t> out;
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

// Recebe nonce(12) + ciphertext + tag(16), retorna plaintext
std::vector<uint8_t> aead_decrypt(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& enc,
                                   const std::string& algo) {
    if ((int)enc.size() < NONCE_BYTES + TAG_BYTES)
        throw std::runtime_error("aead_decrypt: buffer too small");

    const EVP_CIPHER* cipher = (algo == "AES-GCM")
        ? EVP_aes_256_gcm()
        : EVP_chacha20_poly1305();

    const uint8_t* nonce = enc.data();
    const uint8_t* ct    = enc.data() + NONCE_BYTES;
    int ct_len = (int)enc.size() - NONCE_BYTES - TAG_BYTES;
    const uint8_t* tag   = ct + ct_len;

    std::vector<uint8_t> pt(ct_len);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    check_openssl(EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr), "DecInit");
    check_openssl(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_BYTES, nullptr), "SetIVLen");
    check_openssl(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce), "DecInit2");

    int outl = 0, totl = 0;
    check_openssl(EVP_DecryptUpdate(ctx, pt.data(), &outl, ct, ct_len), "DecUpdate");
    totl = outl;
    check_openssl(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_BYTES,
                  const_cast<uint8_t*>(tag)), "SetTag");
    check_openssl(EVP_DecryptFinal_ex(ctx, pt.data() + totl, &outl), "DecFinal");
    EVP_CIPHER_CTX_free(ctx);

    return pt;
}


// =============================================================================
// 4. MEDICAO POR ETAPA
// =============================================================================

struct StepMeas {
    int    proc_idx;
    double t_verify;    // ns
    double t_sign;      // ns
    double t_encrypt;   // ns
    double t_decrypt;   // ns
    size_t msg_size;    // bytes
};


// =============================================================================
// 5. SIMULACAO DA CADEIA  (Sign-then-Encrypt)
// =============================================================================

// Executa a cadeia completa e devolve um único StepMeas com os tempos acumulados.
StepMeas simulate_chain(
    const std::vector<uint8_t>&              payload,
    const std::string&                       sig_algo,
    const std::string&                       conf_algo,
    const std::vector<KeyPair*>&             keypairs,
    const std::vector<uint8_t>&              conf_key)
{
    std::vector<uint8_t> current_plain = payload;
    std::vector<uint8_t> current_enc;   // nonce+ct+tag
    std::vector<uint8_t> current_sig;

    double total_verify = 0, total_sign = 0, total_enc = 0, total_dec = 0;
    size_t msg_size = 0;

    for (int idx = 0; idx < (int)keypairs.size(); ++idx) {
        EVP_PKEY* priv = keypairs[idx]->pkey;

        // ── 1. DECIFRAGEM ─────────────────────────────────────────────────
        if (idx > 0 && conf_algo != "None") {
            int64_t t0 = now_ns();
            current_plain = aead_decrypt(conf_key, current_enc, conf_algo);
            total_dec += (double)(now_ns() - t0);
        }

        // ── 2. VERIFICACAO sobre o plaintext decifrado ────────────────────
        if (idx > 0) {
            EVP_PKEY* prev_pub = keypairs[idx - 1]->pkey;
            int64_t t0 = now_ns();
            do_verify(prev_pub, current_plain, current_sig, sig_algo);
            total_verify += (double)(now_ns() - t0);
        }

        // ── 3. ACUMULACAO ─────────────────────────────────────────────────
        if (idx > 0) {
            current_plain.insert(current_plain.end(),
                                 current_sig.begin(), current_sig.end());
        }

        // ── 4. ASSINATURA sobre o plaintext acumulado (ANTES de cifrar) ───
        int64_t t0 = now_ns();
        current_sig = do_sign(priv, current_plain, sig_algo);
        total_sign += (double)(now_ns() - t0);

        // ── 5. CIFRAGEM do plaintext acumulado (DEPOIS de assinar) ────────
        if (conf_algo != "None") {
            t0 = now_ns();
            current_enc = aead_encrypt(conf_key, current_plain, conf_algo);
            total_enc += (double)(now_ns() - t0);
        }

        // ── Tamanho da mensagem (mantém o valor do último passo) ──────────
        if (conf_algo != "None") {
            msg_size = current_enc.size() + current_sig.size();
        } else {
            msg_size = current_plain.size() + current_sig.size();
        }
    }

    return {(int)keypairs.size(), total_verify, total_sign, total_enc, total_dec, msg_size};
}


// =============================================================================
// 6. ESTATISTICAS
// =============================================================================

struct Stats {
    double mean, std, ci_lo, ci_hi;
    int n;
};

Stats compute_stats(const std::vector<double>& vals) {
    int n = (int)vals.size();
    if (n < 2) {
        double m = n == 1 ? vals[0] : 0.0;
        return {m, 0.0, m, m, n};
    }
    double m = std::accumulate(vals.begin(), vals.end(), 0.0) / n;
    double sq = 0;
    for (double v : vals) sq += (v - m) * (v - m);
    double sd = std::sqrt(sq / (n - 1));
    double mg = CI_Z * sd / std::sqrt((double)n);
    return {m, sd, m - mg, m + mg, n};
}


// =============================================================================
// 7. RESULTADO
// =============================================================================

struct Result {
    std::string sig_algo, conf_algo;
    int payload_size, num_processes, process_idx;
    // verify
    double verify_mean, verify_std, verify_ci_lo, verify_ci_hi;
    // sign
    double sign_mean, sign_std, sign_ci_lo, sign_ci_hi;
    // encrypt
    double enc_mean, enc_std, enc_ci_lo, enc_ci_hi;
    // decrypt
    double dec_mean, dec_std, dec_ci_lo, dec_ci_hi;
    double msg_size;
    // throughput
    double tp_mean, tp_std, tp_ci_lo, tp_ci_hi;
};


// =============================================================================
// 8. LOOP PRINCIPAL
// =============================================================================

std::vector<Result> run_benchmark(bool verbose) {
    int max_procs = *std::max_element(PROCESS_COUNTS.begin(), PROCESS_COUNTS.end());

    std::cout << "Gerando chaves RSA e Ed25519..." << std::flush;
    std::vector<KeyPair> rsa_kps(max_procs), ed_kps(max_procs);
    for (int i = 0; i < max_procs; ++i) {
        rsa_kps[i] = generate_rsa_keypair();
        ed_kps[i]  = generate_ed25519_keypair();
    }
    std::vector<uint8_t> aes_key    = random_bytes(AES_KEY_BYTES);
    std::vector<uint8_t> chacha_key = random_bytes(CHACHA_KEY_BYTES);
    std::cout << " prontas.\n\n";

    std::vector<Result> results;
    int total = (int)(SIG_ALGORITHMS.size() * CONF_ALGORITHMS.size() *
                      PAYLOAD_SIZES.size()  * PROCESS_COUNTS.size());
    int done = 0;

    for (const auto& sig_algo : SIG_ALGORITHMS) {
        for (const auto& conf_algo : CONF_ALGORITHMS) {
            for (int psize : PAYLOAD_SIZES) {
                for (int nproc : PROCESS_COUNTS) {

                    // seleciona keypairs e chave simétrica
                    std::vector<KeyPair*> kps(nproc);
                    for (int i = 0; i < nproc; ++i)
                        kps[i] = (sig_algo == "RSA") ? &rsa_kps[i] : &ed_kps[i];

                    const auto& ckey = (conf_algo == "AES-GCM") ? aes_key : chacha_key;

                    // acumula um StepMeas total por repetição
                    std::vector<StepMeas> chain_meas;

                    for (int rep = 0; rep < REPETITIONS; ++rep) {
                        auto payload = random_bytes(psize);
                        chain_meas.push_back(
                            simulate_chain(payload, sig_algo, conf_algo, kps, ckey));
                    }

                    auto extract = [&](auto fn) {
                        std::vector<double> v;
                        for (auto& s : chain_meas) v.push_back(fn(s));
                        return v;
                    };

                    auto vs  = compute_stats(extract([](auto& s){ return s.t_verify;  }));
                    auto ss  = compute_stats(extract([](auto& s){ return s.t_sign;    }));
                    auto es  = compute_stats(extract([](auto& s){ return s.t_encrypt; }));
                    auto ds  = compute_stats(extract([](auto& s){ return s.t_decrypt; }));

                    double msz = 0;
                    for (auto& s : chain_meas) msz += (double)s.msg_size;
                    msz /= chain_meas.size();

                    // throughput da cadeia: 1 / soma de todos os tempos acumulados
                    std::vector<double> chain_s;
                    for (auto& s : chain_meas) {
                        double t = (s.t_decrypt + s.t_verify + s.t_sign + s.t_encrypt) * 1e-9;
                        chain_s.push_back(t > 0 ? 1.0 / t : 0.0);
                    }
                    auto tp = compute_stats(chain_s);

                    results.push_back({
                        sig_algo, conf_algo, psize, nproc, -1,
                        vs.mean, vs.std, vs.ci_lo, vs.ci_hi,
                        ss.mean, ss.std, ss.ci_lo, ss.ci_hi,
                        es.mean, es.std, es.ci_lo, es.ci_hi,
                        ds.mean, ds.std, ds.ci_lo, ds.ci_hi,
                        msz,
                        tp.mean, tp.std, tp.ci_lo, tp.ci_hi
                    });

                    ++done;
                    if (verbose) {
                        std::cout << "  [" << std::setw(4) << done << "/" << total << "] "
                                  << std::fixed << std::setprecision(1)
                                  << (100.0 * done / total) << "%  "
                                  << std::left << std::setw(8) << sig_algo << " | "
                                  << std::setw(18) << conf_algo << " | "
                                  << "payload=" << std::setw(5) << psize << "B | "
                                  << "procs=" << nproc << "\n";
                    }
                }
            }
        }
    }
    return results;
}


// =============================================================================
// 9. SAIDA CSV
// =============================================================================

static const std::vector<std::string> HEADER = {
    "sig_algo","conf_algo","payload_size_bytes","num_processes","process_idx",
    "verify_mean_ns","verify_std_ns","verify_ci95_lo_ns","verify_ci95_hi_ns",
    "sign_mean_ns","sign_std_ns","sign_ci95_lo_ns","sign_ci95_hi_ns",
    "encrypt_mean_ns","encrypt_std_ns","encrypt_ci95_lo_ns","encrypt_ci95_hi_ns",
    "decrypt_mean_ns","decrypt_std_ns","decrypt_ci95_lo_ns","decrypt_ci95_hi_ns",
    "msg_size_bytes",
    "throughput_mean_msg_s","throughput_std_msg_s",
    "throughput_ci95_lo_msg_s","throughput_ci95_hi_msg_s"
};

std::string fmt(double v, int prec = 2) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(prec) << v;
    return ss.str();
}

void export_csv(const std::vector<Result>& results, const std::string& path) {
    std::ofstream f(path);
    // header
    for (int i = 0; i < (int)HEADER.size(); ++i)
        f << HEADER[i] << (i + 1 < (int)HEADER.size() ? "," : "\n");

    for (const auto& r : results) {
        f << r.sig_algo      << ","
          << r.conf_algo     << ","
          << r.payload_size  << ","
          << r.num_processes << ","
          << r.process_idx   << ","
          << fmt(r.verify_mean)  << "," << fmt(r.verify_std)  << ","
          << fmt(r.verify_ci_lo) << "," << fmt(r.verify_ci_hi) << ","
          << fmt(r.sign_mean)    << "," << fmt(r.sign_std)    << ","
          << fmt(r.sign_ci_lo)   << "," << fmt(r.sign_ci_hi)   << ","
          << fmt(r.enc_mean)     << "," << fmt(r.enc_std)     << ","
          << fmt(r.enc_ci_lo)    << "," << fmt(r.enc_ci_hi)    << ","
          << fmt(r.dec_mean)     << "," << fmt(r.dec_std)     << ","
          << fmt(r.dec_ci_lo)    << "," << fmt(r.dec_ci_hi)    << ","
          << fmt(r.msg_size, 0)  << ","
          << fmt(r.tp_mean)      << "," << fmt(r.tp_std)      << ","
          << fmt(r.tp_ci_lo)     << "," << fmt(r.tp_ci_hi)
          << "\n";
    }
    std::cout << "\nCSV salvo em: " << path << "\n";
}

void print_summary(const std::vector<Result>& results) {
    std::cout << "\n" << std::string(108, '=') << "\n";
    std::cout << "RESUMO  -  process_idx = -1  (cadeia completa)\n";
    std::cout << std::string(108, '=') << "\n";
    std::cout << std::left
              << std::setw(10) << "SIG"
              << std::setw(20) << "CONF"
              << std::right
              << std::setw(10) << "PAYLOAD"
              << std::setw(6)  << "PROCS"
              << std::setw(16) << "VAZAO(msg/s)"
              << std::setw(14) << "MSG_SIZE(B)"
              << "\n";
    std::cout << std::string(108, '-') << "\n";
    for (const auto& r : results) {
        std::cout << std::left
                  << std::setw(10) << r.sig_algo
                  << std::setw(20) << r.conf_algo
                  << std::right
                  << std::setw(10) << r.payload_size
                  << std::setw(6)  << r.num_processes
                  << std::setw(16) << std::fixed << std::setprecision(1) << r.tp_mean
                  << std::setw(14) << std::fixed << std::setprecision(0) << r.msg_size
                  << "\n";
    }
    std::cout << std::string(108, '=') << "\n";
}


// =============================================================================
// 10. MAIN
// =============================================================================

int main(int argc, char* argv[]) {
    std::string output = "crypto_chain_results_cpp.csv";
    bool quiet = false;

    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--output" && i + 1 < argc)
            output = argv[++i];
        else if (std::string(argv[i]) == "--quiet")
            quiet = true;
    }

    std::cout << std::string(60, '=') << "\n";
    std::cout << "  Benchmark: Cadeias de Assinatura Criptografica\n";
    std::cout << "  Linguagem : C++17 + OpenSSL\n";
    std::cout << "  Assinatura : RSA-2048-PSS-SHA256, Ed25519\n";
    std::cout << "  Conf.      : None, AES-256-GCM, ChaCha20-Poly1305\n";
    std::cout << "  Payloads   : 8..1024 bytes\n";
    std::cout << "  Processos  : 1..8\n";
    std::cout << "  Reps/cen.  : " << REPETITIONS << "   IC 95%\n";
    std::cout << std::string(60, '=') << "\n\n";

    auto results = run_benchmark(!quiet);
    print_summary(results);
    export_csv(results, output);

    return 0;
}
