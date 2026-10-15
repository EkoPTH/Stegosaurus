/*
 * core.js - port logika Java (Stego.java, Ciphers.java) ke JavaScript.
 * Bisa dipakai di browser (window.Core) maupun Node.js (module.exports).
 *
 *  - MD5, DES-CBC (PKCS5 padding), PBEWithMD5AndDES (PKCS#5 v1.5)
 *  - Parser/pembuat AU, dekoder AU -> sampel float untuk Web Audio
 *  - Embed / Extract LSB (format identik dengan Stego.java)
 *  - Delta Cipher (port java.util.Random + String.hashCode)
 */
(function (root) {
  'use strict';

  // ------------------------------------------------------------------ MD5
  function md5(bytes) {
    function rotl(x, n) { return (x << n) | (x >>> (32 - n)); }
    var S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    var K = new Int32Array(64);
    for (var i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;

    var len = bytes.length;
    var padLen = ((len + 8) >> 6 << 6) + 64;
    var buf = new Uint8Array(padLen);
    buf.set(bytes);
    buf[len] = 0x80;
    var dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, (len * 8) >>> 0, true);
    dv.setUint32(padLen - 4, Math.floor(len / 536870912), true);

    var a0 = 0x67452301 | 0, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476 | 0;
    var M = new Int32Array(16);
    for (var off = 0; off < padLen; off += 64) {
      for (var j = 0; j < 16; j++) M[j] = dv.getInt32(off + j * 4, true);
      var A = a0, B = b0, C = c0, D = d0;
      for (var k = 0; k < 64; k++) {
        var F, g;
        if (k < 16) { F = (B & C) | (~B & D); g = k; }
        else if (k < 32) { F = (D & B) | (~D & C); g = (5 * k + 1) % 16; }
        else if (k < 48) { F = B ^ C ^ D; g = (3 * k + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * k) % 16; }
        F = (F + A + K[k] + M[g]) | 0;
        A = D; D = C; C = B;
        B = (B + rotl(F, S[k])) | 0;
      }
      a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
    }
    var out = new Uint8Array(16), ov = new DataView(out.buffer);
    ov.setInt32(0, a0, true); ov.setInt32(4, b0, true); ov.setInt32(8, c0, true); ov.setInt32(12, d0, true);
    return out;
  }

  // ------------------------------------------------------------------ DES
  var IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
  var FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
  var E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
  var P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
  var PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
  var PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
  var SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
  var SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
      4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
      0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
      13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
      10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
      4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
      9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
      1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
      7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
  ];

  function bitsOf(bytes) {
    var bits = new Uint8Array(bytes.length * 8);
    for (var i = 0; i < bytes.length; i++)
      for (var j = 0; j < 8; j++) bits[i * 8 + j] = (bytes[i] >> (7 - j)) & 1;
    return bits;
  }
  function bytesOf(bits) {
    var out = new Uint8Array(bits.length / 8);
    for (var i = 0; i < out.length; i++) {
      var v = 0;
      for (var j = 0; j < 8; j++) v = (v << 1) | bits[i * 8 + j];
      out[i] = v;
    }
    return out;
  }
  function permute(src, table) {
    var out = new Uint8Array(table.length);
    for (var i = 0; i < table.length; i++) out[i] = src[table[i] - 1];
    return out;
  }

  function desSubkeys(key8) {
    var kb = permute(bitsOf(key8), PC1);
    var C = kb.slice(0, 28), D = kb.slice(28);
    var keys = [];
    for (var r = 0; r < 16; r++) {
      for (var s = 0; s < SHIFTS[r]; s++) {
        C = rotLeft1(C); D = rotLeft1(D);
      }
      var CD = new Uint8Array(56);
      CD.set(C); CD.set(D, 28);
      keys.push(permute(CD, PC2));
    }
    return keys;
  }
  function rotLeft1(a) {
    var out = new Uint8Array(a.length);
    for (var i = 0; i < a.length - 1; i++) out[i] = a[i + 1];
    out[a.length - 1] = a[0];
    return out;
  }

  function desBlock(block8, keys, decrypt) {
    var bits = permute(bitsOf(block8), IP);
    var L = bits.slice(0, 32), R = bits.slice(32);
    for (var r = 0; r < 16; r++) {
      var k = keys[decrypt ? 15 - r : r];
      var er = permute(R, E);
      var f = new Uint8Array(32);
      for (var s = 0; s < 8; s++) {
        var o = s * 6;
        var x = er[o] ^ k[o], y = er[o + 1] ^ k[o + 1], z = er[o + 2] ^ k[o + 2],
          w = er[o + 3] ^ k[o + 3], v = er[o + 4] ^ k[o + 4], u = er[o + 5] ^ k[o + 5];
        var row = (x << 1) | u;
        var col = (y << 3) | (z << 2) | (w << 1) | v;
        var val = SBOX[s][row * 16 + col];
        f[s * 4] = (val >> 3) & 1; f[s * 4 + 1] = (val >> 2) & 1;
        f[s * 4 + 2] = (val >> 1) & 1; f[s * 4 + 3] = val & 1;
      }
      var pf = permute(f, P);
      var newR = new Uint8Array(32);
      for (var i = 0; i < 32; i++) newR[i] = L[i] ^ pf[i];
      L = R; R = newR;
    }
    var pre = new Uint8Array(64);
    pre.set(R); pre.set(L, 32);
    return bytesOf(permute(pre, FP));
  }

  /** DES-CBC + PKCS5 padding */
  function desCbcEncrypt(data, key8, iv8) {
    var keys = desSubkeys(key8);
    var pad = 8 - (data.length % 8);
    var padded = new Uint8Array(data.length + pad);
    padded.set(data);
    for (var i = data.length; i < padded.length; i++) padded[i] = pad;
    var out = new Uint8Array(padded.length), prev = iv8;
    for (var off = 0; off < padded.length; off += 8) {
      var blk = new Uint8Array(8);
      for (var j = 0; j < 8; j++) blk[j] = padded[off + j] ^ prev[j];
      prev = desBlock(blk, keys, false);
      out.set(prev, off);
    }
    return out;
  }

  /** DES-CBC + PKCS5 unpadding. Melempar Error jika padding salah (password salah). */
  function desCbcDecrypt(data, key8, iv8) {
    if (data.length === 0 || data.length % 8 !== 0) throw new Error('Panjang ciphertext tidak valid');
    var keys = desSubkeys(key8);
    var out = new Uint8Array(data.length), prev = iv8;
    for (var off = 0; off < data.length; off += 8) {
      var blk = data.subarray(off, off + 8);
      var dec = desBlock(blk, keys, true);
      for (var j = 0; j < 8; j++) out[off + j] = dec[j] ^ prev[j];
      prev = blk;
    }
    var pad = out[out.length - 1];
    if (pad < 1 || pad > 8) throw new Error('Padding salah');
    for (var i = out.length - pad; i < out.length; i++)
      if (out[i] !== pad) throw new Error('Padding salah');
    return out.subarray(0, out.length - pad);
  }

  // ------------------------------------------- PBEWithMD5AndDES (Stego.java)
  var SALT = new Uint8Array([0xc7, 0x73, 0x21, 0x8c, 0x7e, 0xc8, 0xee, 0x99]);
  var ITER = 20;

  function pbeDeriveKeyIv(password) {
    // SunJCE (PBEWithMD5AndDES) hanya menerima password ASCII; Java melempar
    // "Password is not ASCII" untuk karakter lain, jadi kita menolak dengan cara sama.
    var pw = new Uint8Array(password.length);
    for (var i = 0; i < password.length; i++) {
      var cc = password.charCodeAt(i);
      if (cc > 0x7f) throw new Error('Password hanya boleh berisi karakter ASCII (tanpa huruf beraksen/emoji).');
      pw[i] = cc;
    }
    var buf = new Uint8Array(pw.length + SALT.length);
    buf.set(pw); buf.set(SALT, pw.length);
    var d = md5(buf);
    for (var n = 1; n < ITER; n++) d = md5(d);
    return { key: d.slice(0, 8), iv: d.slice(8, 16) };
  }
  function pbeEncrypt(bytes, password) {
    var k = pbeDeriveKeyIv(password);
    return desCbcEncrypt(bytes, k.key, k.iv);
  }
  function pbeDecrypt(bytes, password) {
    var k = pbeDeriveKeyIv(password);
    return desCbcDecrypt(bytes, k.key, k.iv);
  }

  // ------------------------------------------------------------------ AU
  var AU_ENC = {
    1: 'μ-law 8-bit', 2: 'PCM 8-bit', 3: 'PCM 16-bit', 4: 'PCM 24-bit', 5: 'PCM 32-bit',
    6: 'Float 32-bit', 7: 'Float 64-bit', 27: 'A-law 8-bit'
  };

  function parseAU(buf) {
    var u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    if (u8.length < 24) throw new Error('File terlalu kecil untuk berformat AU');
    var dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    if (dv.getUint32(0, false) !== 0x2e736e64) throw new Error('Bukan file .au (magic ".snd" tidak ditemukan)');
    var offset = dv.getUint32(4, false);
    var size = dv.getUint32(8, false);
    var encoding = dv.getUint32(12, false);
    var rate = dv.getUint32(16, false);
    var channels = dv.getUint32(20, false);
    if (offset < 24 || offset > u8.length) throw new Error('Header AU tidak valid');
    var avail = u8.length - offset;
    var dataLen = (size === 0xffffffff || size > avail) ? avail : size;
    return {
      bytes: u8, dataOffset: offset, dataLength: dataLen,
      encoding: encoding, encodingName: AU_ENC[encoding] || ('encoding ' + encoding),
      sampleRate: rate, channels: channels
    };
  }

  function buildAU(sampleRate, channels, encoding, dataBytes) {
    var out = new Uint8Array(24 + dataBytes.length);
    var dv = new DataView(out.buffer);
    dv.setUint32(0, 0x2e736e64, false);
    dv.setUint32(4, 24, false);
    dv.setUint32(8, dataBytes.length, false);
    dv.setUint32(12, encoding, false);
    dv.setUint32(16, sampleRate, false);
    dv.setUint32(20, channels, false);
    out.set(dataBytes, 24);
    return out;
  }

  /** Buat AU contoh (nada sinus PCM 16-bit mono) untuk keperluan uji. */
  function makeSampleAU(seconds, rate, freq) {
    var n = Math.floor(seconds * rate);
    var data = new Uint8Array(n * 2), dv = new DataView(data.buffer);
    for (var i = 0; i < n; i++) {
      var v = Math.sin(2 * Math.PI * freq * i / rate) * 0.4 + (Math.random() - 0.5) * 0.02;
      dv.setInt16(i * 2, Math.max(-1, Math.min(1, v)) * 32767, false);
    }
    return buildAU(rate, 1, 3, data);
  }

  function ulawToLinear(u) {
    u = ~u & 0xff;
    var t = (((u & 0x0f) << 3) + 0x84) << ((u & 0x70) >> 4);
    return ((u & 0x80) ? (0x84 - t) : (t - 0x84)) / 32768;
  }
  function alawToLinear(a) {
    a ^= 0x55;
    var t = (a & 0x0f) << 4, seg = (a & 0x70) >> 4;
    if (seg === 0) t += 8;
    else if (seg === 1) t += 0x108;
    else t = (t + 0x108) << (seg - 1);
    return ((a & 0x80) ? t : -t) / 32768;
  }

  /** Dekode data AU menjadi array Float32 per kanal (untuk Web Audio). */
  function decodeAU(au) {
    var ch = Math.max(1, au.channels);
    var bps = { 1: 1, 2: 1, 3: 2, 4: 3, 5: 4, 6: 4, 7: 8, 27: 1 }[au.encoding];
    if (!bps) throw new Error('Encoding AU tidak didukung untuk diputar: ' + au.encoding);
    var frames = Math.floor(au.dataLength / (bps * ch));
    var chans = [];
    for (var c = 0; c < ch; c++) chans.push(new Float32Array(frames));
    var dv = new DataView(au.bytes.buffer, au.bytes.byteOffset + au.dataOffset, au.dataLength);
    for (var f = 0; f < frames; f++) {
      for (var c2 = 0; c2 < ch; c2++) {
        var p = (f * ch + c2) * bps, v;
        switch (au.encoding) {
          case 1: v = ulawToLinear(dv.getUint8(p)); break;
          case 27: v = alawToLinear(dv.getUint8(p)); break;
          case 2: v = dv.getInt8(p) / 128; break;
          case 3: v = dv.getInt16(p, false) / 32768; break;
          case 4: v = ((dv.getInt8(p) << 16) | (dv.getUint8(p + 1) << 8) | dv.getUint8(p + 2)) / 8388608; break;
          case 5: v = dv.getInt32(p, false) / 2147483648; break;
          case 6: v = dv.getFloat32(p, false); break;
          default: v = dv.getFloat64(p, false);
        }
        chans[c2][f] = v;
      }
    }
    return { channels: chans, sampleRate: au.sampleRate };
  }

  // ------------------------------------------------- LSB (Stego.encode/decode)
  // Format identik dengan Stego.java:
  //   byte data ke-1..32 : panjang ciphertext (32 bit, MSB dulu)
  //   byte data ke-33..  : ciphertext, 8 bit per byte, MSB dulu
  //   satu bit disimpan di LSB satu byte audio; byte ke-0 tidak dipakai.

  /** Kapasitas maksimum (byte ciphertext) untuk audio tertentu. */
  function capacityBytes(au) {
    return Math.max(0, Math.floor((au.dataLength - 1 - 32) / 8));
  }

  /** @returns {Uint8Array} salinan file AU dengan ciphertext tertanam */
  function embed(auFileBytes, plainBytes, password) {
    var au = parseAU(auFileBytes);
    var cipher = pbeEncrypt(plainBytes, password);
    var needed = 1 + 32 + cipher.length * 8;
    if (needed > au.dataLength) {
      throw new Error('Audio terlalu kecil. Butuh ' + needed + ' byte data audio, tersedia ' + au.dataLength +
        ' (kapasitas maks. ± ' + capacityBytes(au) + ' byte ciphertext).');
    }
    var out = new Uint8Array(au.bytes); // salinan
    var base = au.dataOffset;
    var i = 1, j, k;
    var len = cipher.length;
    for (j = 31; j >= 0; j--) {
      out[base + i] = (out[base + i] & 0xfe) | ((len >>> j) & 1);
      i++;
    }
    for (k = 0; k < cipher.length; k++) {
      for (j = 7; j >= 0; j--) {
        out[base + i] = (out[base + i] & 0xfe) | ((cipher[k] >> j) & 1);
        i++;
      }
    }
    return out;
  }

  /** @returns {Uint8Array} plaintext. Melempar Error bila data tidak ada / password salah. */
  function extract(auFileBytes, password) {
    var au = parseAU(auFileBytes);
    if (au.dataLength < 33) throw new Error('Audio terlalu kecil');
    var base = au.dataOffset;
    var i = 1, len = 0, j;
    for (j = 0; j < 32; j++) {
      len = (len * 2) + (au.bytes[base + i] & 1);
      i++;
    }
    if (len <= 0 || len % 8 !== 0 || 1 + 32 + len * 8 > au.dataLength)
      throw new Error('Tidak ditemukan pesan tersembunyi di audio ini (panjang data tidak masuk akal).');
    var cipher = new Uint8Array(len);
    for (var k = 0; k < len; k++) {
      var v = 0;
      for (j = 0; j < 8; j++) { v = (v << 1) | (au.bytes[base + i] & 1); i++; }
      cipher[k] = v;
    }
    try {
      return pbeDecrypt(cipher, password);
    } catch (e) {
      throw new Error('Gagal dekripsi: password salah atau audio tidak berisi pesan.');
    }
  }

  // ------------------------------------------------ Delta Cipher (Ciphers.java)
  // Port java.util.Random (LCG 48-bit) dan String.hashCode()
  var MASK48 = (1n << 48n) - 1n;
  var MULT = 0x5DEECE66Dn;

  function javaHashCode(s) {
    var h = 0;
    for (var i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
    return h;
  }
  function JavaRandom(seedInt) {
    // new Random(long seed): seed int di-sign-extend menjadi long
    this.seed = (BigInt(seedInt) ^ MULT) & MASK48;
  }
  JavaRandom.prototype.next = function (bits) {
    this.seed = (this.seed * MULT + 0xBn) & MASK48;
    return Number(BigInt.asIntN(32, this.seed >> BigInt(48 - bits)));
  };
  JavaRandom.prototype.nextInt = function (bound) {
    var r = this.next(31), m = bound - 1;
    if ((bound & m) === 0) return Number((BigInt(bound) * BigInt(r)) >> 31n);
    var u = r;
    for (;;) {
      r = u % bound;
      if (((u - r + m) | 0) >= 0) break; // cek overflow int32 seperti di Java
      u = this.next(31);
    }
    return r;
  };

  /** mode 1 = enkripsi, 2 = dekripsi (sama seperti Cipher.ENCRYPT_MODE / DECRYPT_MODE) */
  function deltaCipher(mode, text, password) {
    password = password.replace(/[ \t\n\x0B\f\r]/g, '');
    if (password === '') return '';
    var rnd = new JavaRandom(javaHashCode(password));
    var out = [];
    for (var i = 0; i < text.length; i++) {
      var a = rnd.nextInt(687 - 192) + 192;
      var b = rnd.nextInt(687 - 192) + 192;
      var shift = a - b;
      var code = (mode === 1) ? text.charCodeAt(i) + shift : text.charCodeAt(i) - shift;
      out.push(String.fromCharCode(code & 0xffff));
    }
    return out.join('');
  }

  var Core = {
    md5: md5, pbeEncrypt: pbeEncrypt, pbeDecrypt: pbeDecrypt,
    parseAU: parseAU, buildAU: buildAU, makeSampleAU: makeSampleAU, decodeAU: decodeAU,
    capacityBytes: capacityBytes, embed: embed, extract: extract,
    deltaCipher: deltaCipher, javaHashCode: javaHashCode, JavaRandom: JavaRandom
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = Core;
  else root.Core = Core;
})(typeof window !== 'undefined' ? window : this);
