# SecureFlow Protocol

**SecureFlow** adalah implementasi proof-of-concept dari protokol komunikasi yang aman, privat, dan tahan-kuantum berdasarkan [SecureFlow Whitepaper](https://github.com/eikarna/SecureFlow) dan [Panduan Teknis](https://github.com/eikarna/SecureFlow).

Proyek ini bertujuan untuk menyediakan fondasi fungsional yang mengimplementasikan fitur-fitur inti dari SecureFlow, ditulis dalam **Go**.

## Fitur Saat Ini (Proof-of-Concept)

*   **Komunikasi Berbasis UDP**: Fondasi protokol untuk latensi rendah.
*   **Handshake & Pertukaran Kunci**: Menggunakan **X25519** (Elliptic Curve Diffie-Hellman) untuk membuat kunci sesi dengan *perfect forward secrecy*.
*   **Enkripsi AEAD**: Semua payload dienkripsi menggunakan **ChaCha20-Poly1305** untuk menjamin kerahasiaan dan integritas data.
*   **Struktur Paket Dasar**: Implementasi struktur paket dengan `Version`, `Nonce`, dan `EncryptedPayload`.

## Rencana Pengembangan (Future Work)

- [ ] **Integrasi Post-Quantum Cryptography (PQC)**: Menambahkan **Kyber (ML-KEM)** untuk pertukaran kunci hibrida.
- [ ] **Obfuskasi Tingkat Lanjut**: Implementasi *packet padding*, *dummy packets*, dan *timing obfuscation*.
- [x] **Port Hopping Dinamis**: Menggunakan port yang berbeda untuk setiap koneksi.
- [ ] **Desentralisasi Opsional**: Membangun routing terdesentralisasi yang terinspirasi dari Tor.
- [x] **Mekanisme Hashing**: Menggunakan **BLAKE3** untuk membuat rantai hash antar paket.
- [ ] **Congestion Control**: Implementasi algoritma seperti BBR.
- [x] **Konfigurasi Lanjutan**: Memperluas file konfigurasi.

## Cara Menjalankan

### 1. Prasyarat

- [Go](https://golang.org/dl/) versi 1.18 atau lebih baru.

### 2. Instalasi Dependensi

Proyek ini menggunakan `golang.org/x/crypto`. Dependensi akan diunduh secara otomatis saat membangun.

### 3. Kompilasi

Kompilasi server dan klien:
```bash
# Masuk ke direktori proyek
cd SecureFlow

# Kompilasi server
go build -o secureflow-server ./cmd/secureflow-server

# Kompilasi klien
go build -o secureflow-client ./cmd/secureflow-client
```

### 4. Menjalankan

1.  **Jalankan Server**
    Buka terminal pertama dan jalankan server:
    ```bash
    ./secureflow-server
    ```
    Server akan berjalan dan mendengarkan di `127.0.0.1:5001-5999` sesuai konfigurasi.

2.  **Jalankan Klien**
    Buka terminal kedua dan jalankan klien:
    ```bash
    ./secureflow-client
    ```
    Klien akan terhubung ke server, melakukan handshake, dan Anda bisa mulai mengetik pesan. Tekan `Enter` untuk mengirim.

---
*Proyek ini dibuat berdasarkan dokumen teknis oleh Adnan Syamsafa.*
*Diimplementasikan oleh Gemini 2.5 Pro.*
