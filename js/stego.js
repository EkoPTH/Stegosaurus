/*
 * stego.js - Stegosaurus: steganografi LSB pada gambar + enkripsi sjcl (AES-CCM).
 * Port dari tes.html (Telik Sandi). Algoritma penempatan bit identik dengan aslinya,
 * sehingga gambar buatan versi lama tetap bisa dibaca. Seluruh proses berjalan di
 * browser; tidak ada data yang dikirim ke server. Membutuhkan js/sjcl.js.
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  if (!$('view-stego') || typeof sjcl === 'undefined') return;

  var MAX_MESSAGE_SIZE = 1000;          // batas panjang payload (karakter), sama seperti aslinya
  var canvas = $('s-canvas');
  var ctx = canvas.getContext('2d', { willReadFrequently: true });
  var S = { loaded: false, name: '', original: null };

  // ----------------------------------------------------------- utilitas UI
  var toastTimer;
  function toast(msg) {
    var t = $('toast');
    if (!t) return;
    t.textContent = msg; t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 3500);
  }
  function showResult(ok, msg) {
    var el = $('s-result');
    el.hidden = false;
    el.className = 'result ' + (ok ? 'ok' : 'err');
    el.textContent = msg;
  }
  function clearDownload() {
    var a = $('s-download');
    if (a._url) URL.revokeObjectURL(a._url);
    a._url = null; a.hidden = true; a.removeAttribute('href');
  }
  function bindShow(checkId, inputId) {
    $(checkId).addEventListener('change', function () { $(inputId).type = this.checked ? 'text' : 'password'; });
  }
  bindShow('s-show', 's-pass');
  bindShow('s-show2', 's-pass2');

  // ----------------------------------------------------------- algoritma LSB (port tes.html)
  var getBit = function (number, location) { return ((number >> location) & 1); };
  var setBit = function (number, location, bit) { return (number & ~(1 << location)) | (bit << location); };

  var getBitsFromNumber = function (number) {
    var bits = [];
    for (var i = 0; i < 16; i++) bits.push(getBit(number, i));
    return bits;
  };

  var getNextLocation = function (history, hash, total) {
    var pos = history.length;
    var loc = Math.abs(hash[pos % hash.length] * (pos + 1)) % total;
    while (true) {
      if (loc >= total) {
        loc = 0;
      } else if (history.indexOf(loc) >= 0) {
        loc++;
      } else if ((loc + 1) % 4 === 0) {   // lewati kanal alpha
        loc++;
      } else {
        history.push(loc);
        return loc;
      }
    }
  };

  var getNumberFromBits = function (bytes, history, hash) {
    var number = 0, pos = 0;
    while (pos < 16) {
      var loc = getNextLocation(history, hash, bytes.length);
      var bit = getBit(bytes[loc], 0);
      number = setBit(number, pos, bit);
      pos++;
    }
    return number;
  };

  var getMessageBits = function (message) {
    var messageBits = [];
    for (var i = 0; i < message.length; i++) {
      messageBits = messageBits.concat(getBitsFromNumber(message.charCodeAt(i)));
    }
    return messageBits;
  };

  var encodeMessage = function (colors, hash, message) {
    var messageBits = getBitsFromNumber(message.length);
    messageBits = messageBits.concat(getMessageBits(message));
    var history = [];
    var pos = 0;
    while (pos < messageBits.length) {
      var loc = getNextLocation(history, hash, colors.length);
      colors[loc] = setBit(colors[loc], 0, messageBits[pos]);
      while ((loc + 1) % 4 !== 0) loc++;
      colors[loc] = 255;                  // alpha piksel dipenuhkan agar RGB tidak berubah saat disimpan
      pos++;
    }
  };

  var decodeMessage = function (colors, hash) {
    var history = [];
    var messageSize = getNumberFromBits(colors, history, hash);
    if ((messageSize + 1) * 16 > colors.length * 0.75) return '';
    if (messageSize === 0 || messageSize > MAX_MESSAGE_SIZE) return '';
    var message = [];
    for (var i = 0; i < messageSize; i++) {
      message.push(String.fromCharCode(getNumberFromBits(colors, history, hash)));
    }
    return message.join('');
  };

  // ----------------------------------------------------------- muat gambar
  function capacityChars(w, h) {
    return Math.min(MAX_MESSAGE_SIZE, Math.floor(w * h * 4 * 0.75 / 16) - 1);
  }

  function resetFields() {
    $('s-message').value = ''; $('s-pass').value = ''; $('s-pass2').value = '';
    $('s-revealed').value = '';
    clearDownload(); $('s-result').hidden = true;
  }

  function loadImage(file) {
    var reader = new FileReader();
    reader.onload = function (ev) {
      var img = new Image();
      img.onload = function () {
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        S.original = ctx.getImageData(0, 0, canvas.width, canvas.height);
        S.loaded = true; S.name = file.name;
        $('s-file-label').textContent = file.name;
        $('s-preview').src = ev.target.result; $('s-preview').hidden = false;
        $('s-info').textContent = img.width + ' × ' + img.height + ' px — kapasitas pesan maks. ± ' +
          capacityChars(img.width, img.height) + ' karakter';
        resetFields();
        decode(true);                      // seperti aslinya: coba baca pesan tanpa password
      };
      img.onerror = function () {
        S.loaded = false;
        $('s-file-label').textContent = 'File Not Choosen';
        $('s-preview').hidden = true; $('s-info').textContent = '';
        showResult(false, 'File bukan gambar yang valid.');
      };
      img.src = ev.target.result;
    };
    reader.onerror = function () { showResult(false, 'Gagal membaca file'); };
    reader.readAsDataURL(file);
  }

  $('s-file').addEventListener('change', function () {
    if (this.files[0]) loadImage(this.files[0]);
  });

  // ----------------------------------------------------------- sembunyikan (encode)
  function encode() {
    var message = $('s-message').value, password = $('s-pass').value;
    if (!S.loaded || message === '') {
      showResult(false, 'Opps ! Something is missing !\n1. Select Image File\n2. Write Message.');
      return;
    }
    var payload;
    try {
      payload = password.length > 0 ? sjcl.encrypt(password, message) : JSON.stringify({ text: message });
    } catch (e) {
      showResult(false, 'Gagal mengenkripsi: ' + (e && e.message ? e.message : e));
      return;
    }

    var pixelCount = canvas.width * canvas.height;
    if ((payload.length + 1) * 16 > pixelCount * 4 * 0.75) {
      showResult(false, 'Pesan terlalu besar untuk gambar ini. Pakai gambar yang lebih besar atau pesan lebih pendek.');
      return;
    }
    if (payload.length > MAX_MESSAGE_SIZE) {
      showResult(false, 'Pesan terlalu besar (' + payload.length + ' karakter setelah diproses, batas ' + MAX_MESSAGE_SIZE +
        '). Persingkat pesan' + (password ? ' (enkripsi menambah ± 150 karakter).' : '.'));
      return;
    }

    ctx.putImageData(S.original, 0, 0);    // mulai dari gambar asli agar sisa pesan lama tidak tercampur
    var imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    encodeMessage(imgData.data, sjcl.hash.sha256.hash(password), payload);
    ctx.putImageData(imgData, 0, 0);

    canvas.toBlob(function (blob) {
      if (!blob) { showResult(false, 'Gagal membuat gambar hasil.'); return; }
      var a = $('s-download');
      if (a._url) URL.revokeObjectURL(a._url);
      a._url = URL.createObjectURL(blob);
      var base = S.name.replace(/\.[^.]*$/, '') || 'gambar';
      var name = base + '-stego.png';
      a.href = a._url; a.download = name; a.hidden = false;
      $('s-finish').disabled = false;
      showResult(true, 'SELESAI! Pesan (' + message.length + ' karakter) berhasil disembunyikan: ' + name +
        '\nKlik "Unduh hasil (PNG)" untuk menyimpan. Jangan dikompres (JPG / kirim sebagai foto di WhatsApp) agar pesan tidak rusak.');
    }, 'image/png');
  }

  // ----------------------------------------------------------- kembalikan (decode)
  function decode(auto) {
    if (!S.loaded) {
      if (!auto) showResult(false, 'Opps ! Something is missing !\n1. Select Image File');
      return;
    }
    var password = $('s-pass2').value;
    var imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    var message = decodeMessage(imgData.data, sjcl.hash.sha256.hash(password));

    var obj = null;
    try { obj = JSON.parse(message); } catch (e) { obj = null; }

    if (!obj || typeof obj !== 'object') {
      $('s-revealed').value = '';
      if (!auto) {
        showResult(false, password.length > 0
          ? 'Password salah atau gambar tidak berisi pesan, Coba Kembali !!!'
          : 'Tidak ditemukan pesan tanpa password. Jika pesan memakai password, isi password lalu klik Kembalikan Sandi.');
      }
      return;
    }

    var text;
    if (obj.ct) {
      try { text = sjcl.decrypt(password, message); }
      catch (e) { $('s-revealed').value = ''; showResult(false, 'Password salah, Coba Kembali !!!'); return; }
    } else {
      text = obj.text;
    }
    $('s-revealed').value = String(text);
    $('s-finish').disabled = false;
    showResult(true, 'Pesan ditemukan (' + String(text).length + ' karakter).');
  }

  $('s-encode').addEventListener('click', encode);
  $('s-decode').addEventListener('click', function () { decode(false); });

  // ----------------------------------------------------------- Finish
  $('s-finish').addEventListener('click', function () {
    S = { loaded: false, name: '', original: null };
    $('s-file').value = '';
    $('s-file-label').textContent = 'File Not Choosen';
    $('s-info').textContent = '';
    $('s-preview').hidden = true; $('s-preview').removeAttribute('src');
    canvas.width = 1; canvas.height = 1;
    resetFields();
    $('s-finish').disabled = true;
    toast('Selesai. Form Stegosaurus dikosongkan.');
  });
})();
