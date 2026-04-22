import os, csv, math, time, argparse, statistics
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

#Configuração 
PAYLOAD_SIZES   = [8, 16, 32, 64, 128, 256, 512, 1024]
PROCESS_COUNTS  = list(range(1, 9))
REPETITIONS     = 30
CI_Z            = 1.96

SIG_ALGORITHMS  = ["RSA", "Ed25519"]
CONF_ALGORITHMS = ["None", "AES-GCM", "ChaCha20-Poly1305"]

RSA_KEY_BITS     = 2048
AES_KEY_BYTES    = 32   
CHACHA_KEY_BYTES = 32   


# Chaves
def generate_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_BITS)
    return (priv, priv.public_key())

def generate_ed25519_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    return (priv, priv.public_key())


#Assinaturas
def rsa_sign(priv, data: bytes) -> bytes:
    return priv.sign(data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

def rsa_verify(pub, data: bytes, sig: bytes) -> None:
    pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

def ed25519_sign(priv, data: bytes) -> bytes:
    return priv.sign(data)

def ed25519_verify(pub, data: bytes, sig: bytes) -> None:
    pub.verify(sig, data)


#Confidencialidade

def aesgcm_encrypt(key: bytes, pt: bytes) -> Tuple[bytes, bytes]:
    #(nonce 12 B, ciphertext+tag)
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, pt, None)

def aesgcm_decrypt(key: bytes, nonce: bytes, ct: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct, None)

def chacha20_encrypt(key: bytes, pt: bytes) -> Tuple[bytes, bytes]:
    #(nonce 12 B, ciphertext+tag)
    nonce = os.urandom(12)
    return nonce, ChaCha20Poly1305(key).encrypt(nonce, pt, None)

def chacha20_decrypt(key: bytes, nonce: bytes, ct: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)


#Métricas

@dataclass
class StepMeas:
    proc_idx:  int
    t_verify:  float   # ns  (0 para proc_idx == 0)
    t_sign:    float   # ns
    t_encrypt: float   # ns  (0 se conf == "None")
    t_decrypt: float   # ns  (0 se conf == "None" ou proc_idx == 0)
    msg_size:  int     # bytes da mensagem que sai deste processo


#Cadeia criptográfica

def simulate_chain(
    payload:   bytes,
    sig_algo:  str,
    conf_algo: str,
    keypairs:  list,
    conf_key:  bytes,
) -> StepMeas:
    """Executa a cadeia completa e devolve um único StepMeas com os tempos acumulados."""

    current_plain: bytes           = payload
    current_ct:    Optional[bytes] = None
    current_nonce: Optional[bytes] = None
    current_sig:   Optional[bytes] = None

    total_verify = total_sign = total_enc = total_dec = 0
    msg_size = 0

    for idx, (priv, _) in enumerate(keypairs):

        #Decifragem
        t_dec = 0
        if idx > 0 and conf_algo != "None":
            t0 = time.perf_counter_ns()
            if conf_algo == "AES-GCM":
                current_plain = aesgcm_decrypt(conf_key, current_nonce, current_ct)
            else:
                current_plain = chacha20_decrypt(conf_key, current_nonce, current_ct)
            t_dec = time.perf_counter_ns() - t0

        #Verificação
        t_verify = 0
        if idx > 0:
            prev_pub = keypairs[idx - 1][1]
            t0 = time.perf_counter_ns()
            if sig_algo == "RSA":
                rsa_verify(prev_pub, current_plain, current_sig)
            else:
                ed25519_verify(prev_pub, current_plain, current_sig)
            t_verify = time.perf_counter_ns() - t0

        #Plaintext + assinatura anterior
        if idx > 0:
            current_plain = current_plain + current_sig

        #Assinatura sobre o plaintext acumulado
        t0 = time.perf_counter_ns()
        if sig_algo == "RSA":
            current_sig = rsa_sign(priv, current_plain)
        else:
            current_sig = ed25519_sign(priv, current_plain)
        t_sign = time.perf_counter_ns() - t0

        #Cifragem
        t_enc = 0
        if conf_algo != "None":
            t0 = time.perf_counter_ns()
            if conf_algo == "AES-GCM":
                current_nonce, current_ct = aesgcm_encrypt(conf_key, current_plain)
            else:
                current_nonce, current_ct = chacha20_encrypt(conf_key, current_plain)
            t_enc = time.perf_counter_ns() - t0

        #Tamanho da mensagem (atualizado a cada passo; mantém o valor do último)
        if conf_algo != "None":
            msg_size = len(current_nonce) + len(current_ct) + len(current_sig)
        else:
            msg_size = len(current_plain) + len(current_sig)

        total_verify += t_verify
        total_sign   += t_sign
        total_enc    += t_enc
        total_dec    += t_dec

    return StepMeas(
        proc_idx  = len(keypairs),
        t_verify  = float(total_verify),
        t_sign    = float(total_sign),
        t_encrypt = float(total_enc),
        t_decrypt = float(total_dec),
        msg_size  = msg_size,
    )


#Estatísticas

@dataclass
class Stats:
    mean: float; std: float; ci_lo: float; ci_hi: float; n: int
    '''
    mean:  média aritmética 30 repetições
    std:   desvio padrão amostral (divisor n-1)
    ci_lo: limite inferior do intervalo de confiança 95% → mean - 1.96 * (std / √n)
    ci_hi: limite superior do intervalo de confiança 95% → mean + 1.96 * (std / √n)
    n:     número de amostras usadas no cálculo (30 repetições)
    '''

def compute_stats(vals: List[float]) -> Stats:
    n = len(vals)
    if n < 2:
        m = vals[0] if vals else 0.0
        return Stats(m, 0.0, m, m, n)
    m  = statistics.mean(vals)
    sd = statistics.stdev(vals)
    mg = CI_Z * sd / math.sqrt(n)
    return Stats(m, sd, m - mg, m + mg, n)


#Loop todos os testes

@dataclass
class Result:
    sig_algo: str; conf_algo: str; payload_size: int
    num_processes: int; process_idx: int
    verify_mean: float; verify_std: float; verify_ci_lo: float; verify_ci_hi: float
    sign_mean:   float; sign_std:   float; sign_ci_lo:   float; sign_ci_hi:   float
    enc_mean:    float; enc_std:    float; enc_ci_lo:    float; enc_ci_hi:    float
    dec_mean:    float; dec_std:    float; dec_ci_lo:    float; dec_ci_hi:    float
    msg_size: float
    tp_mean: float; tp_std: float; tp_ci_lo: float; tp_ci_hi: float


def run_benchmark(verbose: bool = True) -> List[Result]:
    print("Gerando chaves RSA e Ed25519")
    rsa_kps    = [generate_rsa_keypair()     for _ in range(max(PROCESS_COUNTS))]
    ed_kps     = [generate_ed25519_keypair() for _ in range(max(PROCESS_COUNTS))]
    aes_key    = os.urandom(AES_KEY_BYTES)
    chacha_key = os.urandom(CHACHA_KEY_BYTES)

    results: List[Result] = []
    total = (len(SIG_ALGORITHMS) * len(CONF_ALGORITHMS) *
             len(PAYLOAD_SIZES)  * len(PROCESS_COUNTS))
    done = 0

    for sig_algo in SIG_ALGORITHMS:
        for conf_algo in CONF_ALGORITHMS:
            for psize in PAYLOAD_SIZES:
                for nproc in PROCESS_COUNTS:

                    kps  = (rsa_kps if sig_algo == "RSA" else ed_kps)[:nproc]
                    ckey = aes_key if conf_algo == "AES-GCM" else chacha_key

                    chain_meas: List[StepMeas] = []

                    for _ in range(REPETITIONS):
                        payload = os.urandom(psize)
                        chain_meas.append(
                            simulate_chain(payload, sig_algo, conf_algo, kps, ckey))

                    vs  = compute_stats([s.t_verify  for s in chain_meas])
                    ss  = compute_stats([s.t_sign    for s in chain_meas])
                    es  = compute_stats([s.t_encrypt for s in chain_meas])
                    ds  = compute_stats([s.t_decrypt for s in chain_meas])
                    msz = statistics.mean([s.msg_size for s in chain_meas])

                    #throughput da cadeia: 1 / soma de todos os tempos acumulados
                    chain_s = [
                        (s.t_decrypt + s.t_verify + s.t_sign + s.t_encrypt) * 1e-9
                        for s in chain_meas
                    ]
                    tp = compute_stats([1.0 / t if t > 0 else 0.0 for t in chain_s])

                    results.append(Result(
                        sig_algo, conf_algo, psize, nproc, -1,
                        vs.mean, vs.std, vs.ci_lo, vs.ci_hi,
                        ss.mean, ss.std, ss.ci_lo, ss.ci_hi,
                        es.mean, es.std, es.ci_lo, es.ci_hi,
                        ds.mean, ds.std, ds.ci_lo, ds.ci_hi,
                        msz,
                        tp.mean, tp.std, tp.ci_lo, tp.ci_hi))

                    done += 1
                    if verbose:
                        print(f"  [{done:4d}/{total}] {100*done/total:5.1f}%  "
                              f"{sig_algo:8s} | {conf_algo:18s} | "
                              f"payload={psize:5d}B | procs={nproc}")

    return results


#CSV

HEADER = [
    "sig_algo","conf_algo","payload_size_bytes","num_processes","process_idx",
    "verify_mean_ns","verify_std_ns","verify_ci95_lo_ns","verify_ci95_hi_ns",
    "sign_mean_ns","sign_std_ns","sign_ci95_lo_ns","sign_ci95_hi_ns",
    "encrypt_mean_ns","encrypt_std_ns","encrypt_ci95_lo_ns","encrypt_ci95_hi_ns",
    "decrypt_mean_ns","decrypt_std_ns","decrypt_ci95_lo_ns","decrypt_ci95_hi_ns",
    "msg_size_bytes",
    "throughput_mean_msg_s","throughput_std_msg_s",
    "throughput_ci95_lo_msg_s","throughput_ci95_hi_msg_s",
]

def export_csv(results: List[Result], path: str) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        for r in results:
            w.writerow([
                r.sig_algo, r.conf_algo, r.payload_size,
                r.num_processes, r.process_idx,
                f"{r.verify_mean:.2f}", f"{r.verify_std:.2f}",
                f"{r.verify_ci_lo:.2f}", f"{r.verify_ci_hi:.2f}",
                f"{r.sign_mean:.2f}", f"{r.sign_std:.2f}",
                f"{r.sign_ci_lo:.2f}", f"{r.sign_ci_hi:.2f}",
                f"{r.enc_mean:.2f}", f"{r.enc_std:.2f}",
                f"{r.enc_ci_lo:.2f}", f"{r.enc_ci_hi:.2f}",
                f"{r.dec_mean:.2f}", f"{r.dec_std:.2f}",
                f"{r.dec_ci_lo:.2f}", f"{r.dec_ci_hi:.2f}",
                f"{r.msg_size:.0f}",
                f"{r.tp_mean:.2f}", f"{r.tp_std:.2f}",
                f"{r.tp_ci_lo:.2f}", f"{r.tp_ci_hi:.2f}",
            ])
    print(f"\nCSV salvo em: {path}")


def print_summary(results: List[Result]) -> None:
    print("\n" + "=" * 108)
    print("RESUMO  –  process_idx = -1  (cadeia completa)")
    print("=" * 108)
    print(f"{'SIG':<10} {'CONF':<20} {'PAYLOAD':>10} {'PROCS':>6}"
          f"  {'VAZAO(msg/s)':>14}  {'MSG_SIZE(B)':>12}")
    print("-" * 108)
    for r in results:
        print(f"{r.sig_algo:<10} {r.conf_algo:<20} {r.payload_size:>10} "
              f"{r.num_processes:>6}  {r.tp_mean:>14.1f}  {r.msg_size:>12.0f}")
    print("=" * 108)


def main() -> None:
    pasta_do_script = os.path.dirname(os.path.abspath(__file__))
    caminho_padrao_csv = os.path.join(pasta_do_script, "crypto_chain_results.csv")

    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default=caminho_padrao_csv)
    ap.add_argument("--quiet",  action="store_true")
    args = ap.parse_args()

    print("=" * 60)
    print("  Benchmark: Cadeias de Assinatura Criptografica")
    print("  Linguagem : Python 3")
    print(f"  Assinatura : {SIG_ALGORITHMS}")
    print(f"  Conf.      : {CONF_ALGORITHMS}")
    print(f"  Payloads   : {PAYLOAD_SIZES}")
    print(f"  Processos  : {PROCESS_COUNTS}")
    print(f"  Reps/cen.  : {REPETITIONS}   IC 95%")
    print("=" * 60 + "\n")

    results = run_benchmark(verbose=not args.quiet)
    print_summary(results)

    export_csv(results, args.output)


if __name__ == "__main__":
    main()
