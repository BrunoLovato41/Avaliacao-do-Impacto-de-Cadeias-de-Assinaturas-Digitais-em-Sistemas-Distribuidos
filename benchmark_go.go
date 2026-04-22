package main

import (
	gocrypto "crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// =============================================================================
// CONFIGURACAO
// =============================================================================

var payloadSizes  = []int{8, 16, 32, 64, 128, 256, 512, 1024}
var processCounts = []int{1, 2, 3, 4, 5, 6, 7, 8}

const (
	repetitions  = 30
	ciZ          = 1.96
	rsaKeyBits   = 2048
	aesKeyBytes  = 32 // AES-256
	nonceBytes   = 12
)

var sigAlgorithms  = []string{"RSA", "Ed25519"}
var confAlgorithms = []string{"None", "AES-GCM", "ChaCha20-Poly1305"}


// =============================================================================
// 1. CHAVES
// =============================================================================

type RSAKeyPair struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

type Ed25519KeyPair struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func generateRSAKeypair() RSAKeyPair {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		panic(err)
	}
	return RSAKeyPair{priv, &priv.PublicKey}
}

func generateEd25519Keypair() Ed25519KeyPair {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return Ed25519KeyPair{priv, pub}
}

// KeyPair genérico para facilitar o loop da cadeia
type KeyPair struct {
	rsaKP *RSAKeyPair
	edKP  *Ed25519KeyPair
}


// =============================================================================
// 2. ASSINATURA
// =============================================================================

func doSign(kp KeyPair, data []byte, algo string) []byte {
	if algo == "RSA" {
		h := sha256.Sum256(data)
		sig, err := rsa.SignPSS(rand.Reader, kp.rsaKP.priv, gocrypto.SHA256, h[:], nil)
		if err != nil {
			panic(err)
		}
		return sig
	}
	// Ed25519
	return ed25519.Sign(kp.edKP.priv, data)
}

func doVerify(kp KeyPair, data, sig []byte, algo string) {
	if algo == "RSA" {
		h := sha256.Sum256(data)
		err := rsa.VerifyPSS(kp.rsaKP.pub, gocrypto.SHA256, h[:], sig, nil)
		if err != nil {
			panic(fmt.Sprintf("RSA verify failed: %v", err))
		}
		return
	}
	// Ed25519
	if !ed25519.Verify(kp.edKP.pub, data, sig) {
		panic("Ed25519 verify failed")
	}
}


// =============================================================================
// 3. CONFIDENCIALIDADE
// =============================================================================

// Retorna nonce(12) + ciphertext + tag(16)
func aeadEncrypt(key, pt []byte, algo string) []byte {
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	var aead cipher.AEAD
	if algo == "AES-GCM" {
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
	} else {
		var err error
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			panic(err)
		}
	}

	ct := aead.Seal(nil, nonce, pt, nil)
	return append(nonce, ct...)
}

// Recebe nonce(12) + ciphertext + tag(16), retorna plaintext
func aeadDecrypt(key, enc []byte, algo string) []byte {
	if len(enc) < nonceBytes {
		panic("aeadDecrypt: buffer too small")
	}
	nonce := enc[:nonceBytes]
	ct    := enc[nonceBytes:]

	var aead cipher.AEAD
	if algo == "AES-GCM" {
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
	} else {
		var err error
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			panic(err)
		}
	}

	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		panic(fmt.Sprintf("aeadDecrypt: %v", err))
	}
	return pt
}


// =============================================================================
// 4. MEDICAO POR ETAPA
// =============================================================================

type StepMeas struct {
	procIdx  int
	tVerify  float64 // ns
	tSign    float64 // ns
	tEncrypt float64 // ns
	tDecrypt float64 // ns
	msgSize  int     // bytes
}


// =============================================================================
// 5. SIMULACAO DA CADEIA  (Sign-then-Encrypt)
// =============================================================================

func simulateChain(
	payload   []byte,
	sigAlgo   string,
	confAlgo  string,
	keypairs  []KeyPair,
	confKey   []byte,
) StepMeas {
	// Executa a cadeia completa e devolve um único StepMeas com os tempos acumulados.
	currentPlain := make([]byte, len(payload))
	copy(currentPlain, payload)
	var currentEnc []byte
	var currentSig []byte

	var totalVerify, totalSign, totalEnc, totalDec float64
	msgSize := 0

	for idx, kp := range keypairs {

		// ── 1. DECIFRAGEM ─────────────────────────────────────────────────
		if idx > 0 && confAlgo != "None" {
			t0 := time.Now()
			currentPlain = aeadDecrypt(confKey, currentEnc, confAlgo)
			totalDec += float64(time.Since(t0).Nanoseconds())
		}

		// ── 2. VERIFICACAO sobre o plaintext decifrado ────────────────────
		if idx > 0 {
			prevKP := keypairs[idx-1]
			t0 := time.Now()
			doVerify(prevKP, currentPlain, currentSig, sigAlgo)
			totalVerify += float64(time.Since(t0).Nanoseconds())
		}

		// ── 3. ACUMULACAO ─────────────────────────────────────────────────
		if idx > 0 {
			currentPlain = append(currentPlain, currentSig...)
		}

		// ── 4. ASSINATURA sobre o plaintext acumulado (ANTES de cifrar) ───
		t0 := time.Now()
		currentSig = doSign(kp, currentPlain, sigAlgo)
		totalSign += float64(time.Since(t0).Nanoseconds())

		// ── 5. CIFRAGEM do plaintext acumulado (DEPOIS de assinar) ────────
		if confAlgo != "None" {
			t0 = time.Now()
			currentEnc = aeadEncrypt(confKey, currentPlain, confAlgo)
			totalEnc += float64(time.Since(t0).Nanoseconds())
		}

		// ── Tamanho da mensagem (mantém o valor do último passo) ──────────
		if confAlgo != "None" {
			msgSize = len(currentEnc) + len(currentSig)
		} else {
			msgSize = len(currentPlain) + len(currentSig)
		}
	}

	return StepMeas{
		procIdx:  len(keypairs),
		tVerify:  totalVerify,
		tSign:    totalSign,
		tEncrypt: totalEnc,
		tDecrypt: totalDec,
		msgSize:  msgSize,
	}
}


// =============================================================================
// 6. ESTATISTICAS
// =============================================================================

type Stats struct {
	mean, std, ciLo, ciHi float64
	n                      int
}

func computeStats(vals []float64) Stats {
	n := len(vals)
	if n < 2 {
		m := 0.0
		if n == 1 {
			m = vals[0]
		}
		return Stats{m, 0, m, m, n}
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	m := sum / float64(n)
	sq := 0.0
	for _, v := range vals {
		sq += (v - m) * (v - m)
	}
	sd := math.Sqrt(sq / float64(n-1))
	mg := ciZ * sd / math.Sqrt(float64(n))
	return Stats{m, sd, m - mg, m + mg, n}
}


// =============================================================================
// 7. RESULTADO
// =============================================================================

type Result struct {
	sigAlgo    string
	confAlgo   string
	payloadSize int
	numProcesses int
	processIdx  int
	// verify
	verifyMean, verifyStd, verifyCiLo, verifyCiHi float64
	// sign
	signMean, signStd, signCiLo, signCiHi float64
	// encrypt
	encMean, encStd, encCiLo, encCiHi float64
	// decrypt
	decMean, decStd, decCiLo, decCiHi float64
	msgSize float64
	// throughput
	tpMean, tpStd, tpCiLo, tpCiHi float64
}


// =============================================================================
// 8. LOOP PRINCIPAL
// =============================================================================

func runBenchmark(verbose bool) []Result {
	maxProcs := 0
	for _, p := range processCounts {
		if p > maxProcs {
			maxProcs = p
		}
	}

	fmt.Print("Gerando chaves RSA e Ed25519...")
	rsaKPs := make([]RSAKeyPair, maxProcs)
	edKPs  := make([]Ed25519KeyPair, maxProcs)
	for i := 0; i < maxProcs; i++ {
		rsaKPs[i] = generateRSAKeypair()
		edKPs[i]  = generateEd25519Keypair()
	}
	aesKey    := make([]byte, aesKeyBytes)
	chachaKey := make([]byte, 32)
	rand.Read(aesKey)
	rand.Read(chachaKey)
	fmt.Println(" prontas.")
	fmt.Println()

	var results []Result
	total := len(sigAlgorithms) * len(confAlgorithms) * len(payloadSizes) * len(processCounts)
	done  := 0

	for _, sigAlgo := range sigAlgorithms {
		for _, confAlgo := range confAlgorithms {
			for _, psize := range payloadSizes {
				for _, nproc := range processCounts {

					// monta slice de KeyPair genérico
					kps := make([]KeyPair, nproc)
					for i := 0; i < nproc; i++ {
						if sigAlgo == "RSA" {
							kps[i] = KeyPair{rsaKP: &rsaKPs[i]}
						} else {
							kps[i] = KeyPair{edKP: &edKPs[i]}
						}
					}

					ckey := aesKey
					if confAlgo == "ChaCha20-Poly1305" {
						ckey = chachaKey
					}

					chainMeas := make([]StepMeas, 0, repetitions)

					for rep := 0; rep < repetitions; rep++ {
						payload := make([]byte, psize)
						rand.Read(payload)
						chainMeas = append(chainMeas,
							simulateChain(payload, sigAlgo, confAlgo, kps, ckey))
					}

					extractF := func(fn func(StepMeas) float64) []float64 {
						v := make([]float64, len(chainMeas))
						for i, s := range chainMeas {
							v[i] = fn(s)
						}
						return v
					}

					vs := computeStats(extractF(func(s StepMeas) float64 { return s.tVerify }))
					ss := computeStats(extractF(func(s StepMeas) float64 { return s.tSign }))
					es := computeStats(extractF(func(s StepMeas) float64 { return s.tEncrypt }))
					ds := computeStats(extractF(func(s StepMeas) float64 { return s.tDecrypt }))

					mszSum := 0.0
					for _, s := range chainMeas {
						mszSum += float64(s.msgSize)
					}
					msz := mszSum / float64(len(chainMeas))

					// throughput da cadeia: 1 / soma de todos os tempos acumulados
					chainS := make([]float64, len(chainMeas))
					for i, s := range chainMeas {
						t := (s.tDecrypt + s.tVerify + s.tSign + s.tEncrypt) * 1e-9
						if t > 0 {
							chainS[i] = 1.0 / t
						}
					}
					tp := computeStats(chainS)

					results = append(results, Result{
						sigAlgo: sigAlgo, confAlgo: confAlgo,
						payloadSize: psize, numProcesses: nproc, processIdx: -1,
						verifyMean: vs.mean, verifyStd: vs.std, verifyCiLo: vs.ciLo, verifyCiHi: vs.ciHi,
						signMean: ss.mean, signStd: ss.std, signCiLo: ss.ciLo, signCiHi: ss.ciHi,
						encMean: es.mean, encStd: es.std, encCiLo: es.ciLo, encCiHi: es.ciHi,
						decMean: ds.mean, decStd: ds.std, decCiLo: ds.ciLo, decCiHi: ds.ciHi,
						msgSize: msz,
						tpMean: tp.mean, tpStd: tp.std, tpCiLo: tp.ciLo, tpCiHi: tp.ciHi,
					})

					done++
					if verbose {
						fmt.Printf("  [%4d/%d] %5.1f%%  %-8s | %-18s | payload=%5dB | procs=%d\n",
							done, total, 100.0*float64(done)/float64(total),
							sigAlgo, confAlgo, psize, nproc)
					}
				}
			}
		}
	}
	return results
}


// =============================================================================
// 9. SAIDA CSV
// =============================================================================

var csvHeader = []string{
	"sig_algo", "conf_algo", "payload_size_bytes", "num_processes", "process_idx",
	"verify_mean_ns", "verify_std_ns", "verify_ci95_lo_ns", "verify_ci95_hi_ns",
	"sign_mean_ns", "sign_std_ns", "sign_ci95_lo_ns", "sign_ci95_hi_ns",
	"encrypt_mean_ns", "encrypt_std_ns", "encrypt_ci95_lo_ns", "encrypt_ci95_hi_ns",
	"decrypt_mean_ns", "decrypt_std_ns", "decrypt_ci95_lo_ns", "decrypt_ci95_hi_ns",
	"msg_size_bytes",
	"throughput_mean_msg_s", "throughput_std_msg_s",
	"throughput_ci95_lo_msg_s", "throughput_ci95_hi_msg_s",
}

func f2(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }
func f0(v float64) string { return strconv.FormatFloat(v, 'f', 0, 64) }

func exportCSV(results []Result, path string) {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	w := csv.NewWriter(file)
	w.Write(csvHeader)

	for _, r := range results {
		w.Write([]string{
			r.sigAlgo, r.confAlgo,
			strconv.Itoa(r.payloadSize),
			strconv.Itoa(r.numProcesses),
			strconv.Itoa(r.processIdx),
			f2(r.verifyMean), f2(r.verifyStd), f2(r.verifyCiLo), f2(r.verifyCiHi),
			f2(r.signMean), f2(r.signStd), f2(r.signCiLo), f2(r.signCiHi),
			f2(r.encMean), f2(r.encStd), f2(r.encCiLo), f2(r.encCiHi),
			f2(r.decMean), f2(r.decStd), f2(r.decCiLo), f2(r.decCiHi),
			f0(r.msgSize),
			f2(r.tpMean), f2(r.tpStd), f2(r.tpCiLo), f2(r.tpCiHi),
		})
	}
	w.Flush()
	fmt.Printf("\nCSV salvo em: %s\n", path)
}

func printSummary(results []Result) {
	sep := fmt.Sprintf("%s", repeatStr("=", 108))
	fmt.Println("\n" + sep)
	fmt.Println("RESUMO  -  process_idx = -1  (cadeia completa)")
	fmt.Println(sep)
	fmt.Printf("%-10s %-20s %10s %6s  %14s  %12s\n",
		"SIG", "CONF", "PAYLOAD", "PROCS", "VAZAO(msg/s)", "MSG_SIZE(B)")
	fmt.Println(repeatStr("-", 108))
	for _, r := range results {
		fmt.Printf("%-10s %-20s %10d %6d  %14.1f  %12.0f\n",
			r.sigAlgo, r.confAlgo, r.payloadSize, r.numProcesses, r.tpMean, r.msgSize)
	}
	fmt.Println(sep)
}

func repeatStr(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}


// =============================================================================
// 10. MAIN
// =============================================================================

func main() {
	output := flag.String("output", "crypto_chain_results_go.csv", "Caminho do CSV de saída")
	quiet  := flag.Bool("quiet", false, "Suprimir progresso")
	flag.Parse()

	fmt.Println(repeatStr("=", 60))
	fmt.Println("  Benchmark: Cadeias de Assinatura Criptografica")
	fmt.Println("  Linguagem : Go")
	fmt.Printf("  Assinatura : %v\n", sigAlgorithms)
	fmt.Printf("  Conf.      : %v\n", confAlgorithms)
	fmt.Printf("  Payloads   : %v\n", payloadSizes)
	fmt.Printf("  Processos  : %v\n", processCounts)
	fmt.Printf("  Reps/cen.  : %d   IC 95%%\n", repetitions)
	fmt.Println(repeatStr("=", 60))
	fmt.Println()

	results := runBenchmark(!*quiet)
	printSummary(results)
	exportCSV(results, *output)
}
