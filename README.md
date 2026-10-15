# Audio Steganography & Cipher Dashboard (versi Web)

Port dari proyek Java (`Dashboard`, `Stego`, `Ciphers`, `Audio`) ke HTML + JavaScript.
Semua proses berjalan di browser; tidak butuh PHP maupun database.

## Cara menjalankan di XAMPP

1. Salin folder `stego-web` ke `C:\xampp\htdocs\` (Linux: `/opt/lampp/htdocs/`).
2. Buka XAMPP Control Panel, lalu **Start** pada modul **Apache**.
3. Buka `http://localhost/stego-web/` di browser.

Struktur:

```
stego-web/
├── index.html
├── css/style.css
└── js/
    ├── core.js   <- logika (MD5, DES, PBEWithMD5AndDES, LSB, Delta Cipher)
    └── app.js    <- antarmuka
```

## Fitur

| Menu | Padanan Java | Keterangan |
|------|--------------|-----------|
| Embed | `Dashboard.EmbedPanel` + `Stego.encode()` | Teks (ketik / file .txt) → enkripsi → disisipkan ke LSB audio `.au` |
| Extract | `Dashboard.ExtractPanel` + `Stego.decode()` | Ambil bit LSB → dekripsi → tampilkan / unduh `.txt` |
| Delta Cipher | `CipherPanel` + `Ciphers.dynamicEncryptionOrDecryption()` | Enkripsi/dekripsi teks berbasis `java.util.Random` |
| Play / Stop | `Audio.java` (`sun.audio`) | Diputar lewat Web Audio API (decoder AU buatan sendiri) |

## Spesifikasi yang dipertahankan

- Enkripsi pesan: **PBEWithMD5AndDES** (PKCS#5 v1.5), salt `C7 73 21 8C 7E C8 EE 99`, 20 iterasi, DES-CBC + PKCS5 padding.
- Penyisipan: 1 bit per byte audio pada **LSB**, mulai dari byte data ke-1 (byte ke-0 tidak dipakai); 32 bit pertama = panjang ciphertext (MSB dulu), lalu isi ciphertext.
- Delta Cipher: seed `Random(password.hashCode())` (spasi pada password dibuang), per karakter `±(nextInt(495)+192) ∓ (nextInt(495)+192)`.

## Kompatibilitas dengan program Java (sudah diuji)

- File `Encrypted-*.au` buatan versi web **identik byte-per-byte** dengan buatan `Stego.java`.
- File buatan Java dapat di-extract versi web, dan sebaliknya.
- Hasil Delta Cipher sama dengan `Ciphers.java` (termasuk password/teks unicode dan emoji).

## Perbedaan dari versi Java

- **Tidak ada batas 154.600 frame.** `Stego.readSND` memakai buffer tetap, sehingga audio yang lebih panjang terpotong saat disimpan. Versi web memakai seluruh audio.
- Pengecekan kapasitas lebih ketat (memperhitungkan 32 bit header panjang).
- Password Embed/Extract **harus ASCII** (aturan PBEWithMD5AndDES di Java: "Password is not ASCII").
- Password salah atau audio tanpa pesan menampilkan pesan error yang jelas (di Java berujung `NullPointerException`).
- Tombol **"Buat audio contoh (.au)"** ditambahkan untuk uji coba, karena file `.au` jarang tersedia.
- `Caesar` dan enkripsi file `Blowfish` di `Ciphers.java` tidak dipindahkan karena tidak dipakai oleh Dashboard.

## Catatan keamanan

PBEWithMD5AndDES, DES, salt tetap, dan LSB steganography adalah teknik klasik yang **lemah menurut standar modern**.

