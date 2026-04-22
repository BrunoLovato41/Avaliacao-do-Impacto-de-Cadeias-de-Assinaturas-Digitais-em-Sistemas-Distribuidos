# Avaliacao-do-Impacto-de-Cadeias-de-Assinaturas-Digitais-em-Sistemas-Distribuidos
Estudo que busca avaliar o impacto de cadeias de assinaturas digitais em sistemas distribuídos. Estudo feito nas linguagens C++, Go e Python com os algoritmos Ed25519 e RSA-2048. 

Este repositório contém os códigos fonte e instruções para reprodução dos experimentos descritos no artigo "Avaliação Experimental do Impacto de Cadeias de Assinaturas Digitais em Sistemas Distribuídos" (WTF 2026). Os benchmarks avaliam o custo computacional e o crescimento estrutural de cadeias de assinatura digital, considerando diferentes algoritmos, tamanhos de payload, número de processos e mecanismos de confidencialidade.

Configuração Experimental  
Algoritmos de assinatura: RSA‑2048‑PSS, Ed25519.  
Confidencialidade: Nenhum, AES‑256‑GCM, ChaCha20‑Poly1305.  
Tamanho do payload: 8, 16, 32, 64, 128, 256, 512, 1024 bytes.  
Número de processos: 1 a 8.  
Repetições por cenário: 30.  
Intervalo de confiança: 95% (z = 1,96).  


O CSV gerado contém as seguintes colunas  
sig_algo: Algoritmo de assinatura (RSA ou Ed25519).  
conf_algo: Mecanismo de confidencialidade (None, AES-GCM, ChaCha20-Poly1305).  
payload_size_bytes: Tamanho do payload original em bytes.  
num_processes: Número de processos na cadeia (1 a 8).  
process_idx: Sempre -1 (indica medição da cadeia completa).  
verify_mean_ns ... decrypt_ci95_hi_ns: Estatísticas (média, desvio, IC 95%) dos tempos de cada operação em nanossegundos.  
msg_size_bytes: Tamanho total da mensagem transmitida (inclui assinaturas, nonce, tag).  
throughput_mean_msg_s …: Estatísticas do throughput (mensagens/segundo).  
