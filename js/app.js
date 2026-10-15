/*
 * app.js - antarmuka Dashboard (pengganti Dashboard.java).
 * Seluruh proses berjalan di browser; tidak ada data yang dikirim ke server.
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var BPS = { 1: 1, 2: 1, 3: 2, 4: 3, 5: 4, 6: 4, 7: 8, 27: 1 };

  var HELP_TEXT =
    'Embed (Teks → Audio)\n' +
    '- Pilih file audio .au\n' +
    '- Ketik teks langsung (Write Text) atau pilih file .txt\n' +
    '- Isi password, lalu klik "Encrypt Audio File"\n' +
    '- Klik "Unduh hasil" untuk menyimpan file audio hasil (<nama>.au)\n\n' +
    'Extract (Audio → Teks)\n' +
    '- Pilih audio hasil Embed, isi password yang sama\n' +
    '- Klik "Extract Text"; teks tampil di kotak bawah\n\n' +
    'Delta Cipher (Telik Sandi 4.0)\n' +
    '- Tulis plainteks di kolom kiri, isi password di kanan bawah\n' +
    '- Pilih "Enkripsi" atau "Dekripsi"; password harus sama saat dekripsi\n\n' +
    'Stegosaurus (Steganografi Gambar)\n' +
    '- Pilih gambar, tulis pesan, isi password (opsional), klik "Sembunyikan Sandi"\n' +
    '- Unduh hasil PNG; jangan dikompres (JPG / foto WhatsApp) agar pesan tidak rusak\n' +
    '- Untuk membaca: pilih gambar hasil, isi password (jika ada), klik "Kembalikan Sandi"\n\n' +
    'Enjoyy !';

  // ----------------------------------------------------------- utilitas
  var toastTimer;
  function toast(msg) {
    var t = $('toast');
    t.textContent = msg; t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 3500);
  }

  function showResult(el, ok, msg) {
    el.hidden = false;
    el.className = 'result ' + (ok ? 'ok' : 'err');
    el.textContent = msg;
  }

  function readBytes(file) {
    return new Promise(function (resolve, reject) {
      var r = new FileReader();
      r.onload = function () { resolve(new Uint8Array(r.result)); };
      r.onerror = function () { reject(new Error('Gagal membaca file')); };
      r.readAsArrayBuffer(file);
    });
  }

  function setDownload(a, bytes, name, mime) {
    if (a._url) URL.revokeObjectURL(a._url);
    a._url = URL.createObjectURL(new Blob([bytes], { type: mime }));
    a.href = a._url; a.download = name; a.hidden = false;
  }
  function clearDownload(a) {
    if (a._url) URL.revokeObjectURL(a._url);
    a._url = null; a.hidden = true; a.removeAttribute('href');
  }

  function describeAU(au) {
    var bps = BPS[au.encoding] || 1, ch = Math.max(1, au.channels);
    var frames = au.dataLength / (bps * ch);
    var dur = au.sampleRate ? (frames / au.sampleRate) : 0;
    return au.encodingName + ', ' + au.sampleRate + ' Hz, ' + ch + ' kanal, ' + dur.toFixed(1) +
      ' dtk — kapasitas ± ' + Core.capacityBytes(au) + ' byte teks';
  }

  // ----------------------------------------------------------- pemutar audio
  var audioCtx = null, activeSource = null;
  function stopAudio() {
    if (activeSource) { try { activeSource.stop(); } catch (e) { /* sudah berhenti */ } activeSource = null; }
  }
  function playAU(bytes) {
    stopAudio();
    var au = Core.parseAU(bytes);
    var dec = Core.decodeAU(au);
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === 'suspended') audioCtx.resume();
    var buf = audioCtx.createBuffer(dec.channels.length, dec.channels[0].length, dec.sampleRate);
    dec.channels.forEach(function (d, i) { buf.copyToChannel(d, i); });
    var src = audioCtx.createBufferSource();
    src.buffer = buf; src.connect(audioCtx.destination);
    src.onended = function () { if (activeSource === src) activeSource = null; };
    src.start();
    activeSource = src;
  }

  // ----------------------------------------------------------- navigasi
  var TITLES = {
    home: 'Beranda',
    embed: 'Encrypt Audio File (Embed Text To Audio File)',
    extract: 'Extract Text From Encrypted Audio',
    cipher: 'Telik sandi 4.0 (Delta Cipher)',
    stego: 'Stegosaurus (Steganografi Gambar)'
  };
  function show(view) {
    stopAudio();
    document.querySelectorAll('.view').forEach(function (v) { v.classList.toggle('active', v.id === 'view-' + view); });
    document.querySelectorAll('.nav[data-view]').forEach(function (b) { b.classList.toggle('active', b.dataset.view === view); });
    $('viewTitle').textContent = TITLES[view];
  }
  document.querySelectorAll('.nav[data-view]').forEach(function (b) {
    b.addEventListener('click', function () { show(b.dataset.view); });
  });
  document.querySelectorAll('[data-goto]').forEach(function (b) {
    b.addEventListener('click', function () { show(b.dataset.goto); });
  });
  $('btnHelp').addEventListener('click', function () {
    $('helpText').textContent = HELP_TEXT;
    $('helpDialog').showModal();
  });

  function bindShow(checkId, inputId) {
    $(checkId).addEventListener('change', function () { $(inputId).type = this.checked ? 'text' : 'password'; });
  }
  bindShow('e-show', 'e-pass');
  bindShow('x-show', 'x-pass');

  // ============================================================ EMBED
  var E = { audioBytes: null, audioName: null, txtBytes: null, txtName: null, outBytes: null };

  function embedLoadAudio(file) {
    stopAudio();
    return readBytes(file).then(function (bytes) {
      var au = Core.parseAU(bytes);
      E.audioBytes = bytes; E.audioName = file.name;
      $('e-audio-label').textContent = file.name;
      $('e-audio-info').textContent = describeAU(au);
      $('e-play').disabled = false; $('e-stop').disabled = false;
      clearDownload($('e-download')); $('e-result').hidden = true;
    }).catch(function (err) {
      E.audioBytes = null;
      $('e-audio-label').textContent = 'File Not Choosen';
      $('e-audio-info').textContent = '';
      $('e-play').disabled = true; $('e-stop').disabled = true;
      showResult($('e-result'), false, err.message);
    });
  }

  $('e-audio').addEventListener('change', function () {
    if (this.files[0]) embedLoadAudio(this.files[0]);
  });
  $('e-txtfile').addEventListener('change', function () {
    var f = this.files[0];
    if (!f) return;
    readBytes(f).then(function (b) {
      E.txtBytes = b; E.txtName = f.name;
      $('e-txtfile-label').textContent = f.name;
    });
  });
  document.querySelectorAll('input[name=e-mode]').forEach(function (r) {
    r.addEventListener('change', function () {
      var write = document.querySelector('input[name=e-mode]:checked').value === 'write';
      $('e-write').hidden = !write; $('e-file').hidden = write;
    });
  });
  $('e-play').addEventListener('click', function () {
    try { playAU(E.audioBytes); } catch (err) { toast(err.message); }
  });
  $('e-stop').addEventListener('click', stopAudio);
  $('e-clear').addEventListener('click', function () { $('e-pass').value = ''; });

  $('e-sample').addEventListener('click', function () {
    var bytes = Core.makeSampleAU(10, 22050, 440);
    embedLoadAudio(new File([bytes], 'contoh.au', { type: 'audio/basic' }));
    toast('Audio contoh (nada 440 Hz, 10 dtk) dimuat.');
  });

  $('e-run').addEventListener('click', function () {
    var res = $('e-result'), pass = $('e-pass').value;
    var writeMode = document.querySelector('input[name=e-mode]:checked').value === 'write';
    var plain = null;
    if (writeMode) {
      var t = $('e-text').value;
      if (t !== '') plain = new TextEncoder().encode(t);
    } else {
      plain = E.txtBytes;
    }
    if (!E.audioBytes || !plain || pass === '') {
      showResult(res, false, 'Opps ! Something is missing !\n1. Select Audio File\n2. Write Text or Select Text File\n3. Enter Password.');
      return;
    }
    try {
      var out = Core.embed(E.audioBytes, plain, pass);
      // Hilangkan kata "Encrypted" dari nama file (mis. Encrypted-lagu.au -> lagu.au)
      var name = E.audioName.replace(/encrypted[-_\s]*/gi, '');
      E.outBytes = out;
      setDownload($('e-download'), out, name, 'audio/basic');
      $('e-finish').disabled = false;
      showResult(res, true, 'Encrypt selesai: ' + name + '\nTeks ' + plain.length + ' byte berhasil disisipkan. Klik "Unduh hasil" untuk menyimpan.');
    } catch (err) {
      showResult(res, false, err.message);
    }
  });

  $('e-finish').addEventListener('click', function () {
    stopAudio();
    E = { audioBytes: null, audioName: null, txtBytes: null, txtName: null, outBytes: null };
    $('e-audio').value = ''; $('e-txtfile').value = '';
    $('e-audio-label').textContent = 'File Not Choosen';
    $('e-txtfile-label').textContent = 'File Not Choosen';
    $('e-audio-info').textContent = '';
    $('e-text').value = ''; $('e-pass').value = '';
    $('e-play').disabled = true; $('e-stop').disabled = true; $('e-finish').disabled = true;
    clearDownload($('e-download')); $('e-result').hidden = true;
    toast('Selesai. Form Embed dikosongkan.');
  });

  // ============================================================ EXTRACT
  var X = { audioBytes: null, audioName: null, textBytes: null };

  $('x-audio').addEventListener('change', function () {
    var f = this.files[0];
    if (!f) return;
    stopAudio();
    readBytes(f).then(function (bytes) {
      var au = Core.parseAU(bytes);
      X.audioBytes = bytes; X.audioName = f.name;
      $('x-audio-label').textContent = f.name;
      $('x-audio-info').textContent = describeAU(au);
      $('x-play').disabled = false; $('x-stop').disabled = false;
      $('x-result').hidden = true; clearDownload($('x-download'));
    }).catch(function (err) {
      X.audioBytes = null;
      $('x-audio-label').textContent = 'File Not Choosen';
      $('x-play').disabled = true; $('x-stop').disabled = true;
      showResult($('x-result'), false, err.message);
    });
  });
  $('x-play').addEventListener('click', function () {
    try { playAU(X.audioBytes); } catch (err) { toast(err.message); }
  });
  $('x-stop').addEventListener('click', stopAudio);
  $('x-clear').addEventListener('click', function () { $('x-pass').value = ''; });

  $('x-run').addEventListener('click', function () {
    var res = $('x-result'), pass = $('x-pass').value;
    if (!X.audioBytes || pass === '') {
      showResult(res, false, 'Opps ! Something is missing !\n1. Select Audio File\n2. Enter Password.');
      return;
    }
    try {
      var plain = Core.extract(X.audioBytes, pass);
      X.textBytes = plain;
      $('x-text').value = new TextDecoder('utf-8').decode(plain);
      // Hilangkan kata "Encrypted" dari nama file hasil (mis. Encrypted-contoh.au -> contoh.au)
      var srcName = X.audioName.replace(/encrypted[-_\s]*/gi, '');
      var name = 'ExtractedText-From-' + srcName + '.txt';
      setDownload($('x-download'), plain, name, 'text/plain');
      $('x-finish').disabled = false;
      showResult(res, true, 'Extract selesai (' + plain.length + ' byte). Klik "Unduh .txt" untuk menyimpan ' + name);
    } catch (err) {
      $('x-text').value = '';
      clearDownload($('x-download'));
      showResult(res, false, err.message);
    }
  });

  $('x-finish').addEventListener('click', function () {
    stopAudio();
    X = { audioBytes: null, audioName: null, textBytes: null };
    $('x-audio').value = '';
    $('x-audio-label').textContent = 'File Not Choosen';
    $('x-audio-info').textContent = '';
    $('x-pass').value = ''; $('x-text').value = '';
    $('x-play').disabled = true; $('x-stop').disabled = true; $('x-finish').disabled = true;
    clearDownload($('x-download')); $('x-result').hidden = true;
    toast('Selesai. Form Extract dikosongkan.');
  });

  // ============================================================ DELTA CIPHER
  // Perilaku mengikuti CipherPanel di Dashboard.java.
  var left = $('c-left'), right = $('c-right'), key = $('c-key');
  var rEnc = $('c-enc'), rDec = $('c-dec');
  var cMode = 1, cDecrypt = false;

  function doJob() {
    var ready = key.value.trim() !== '' && left.value.trim() !== '';
    if (!cDecrypt) {
      rDec.disabled = !ready;
    } else {
      rEnc.disabled = !ready;
    }
    right.value = ready ? Core.deltaCipher(cMode, left.value, key.value) : '';
  }
  left.addEventListener('input', doJob);
  key.addEventListener('input', doJob);

  rEnc.addEventListener('change', function () {
    if (!rEnc.checked) return;
    cMode = 1; cDecrypt = false; rDec.disabled = true;
    doJob();
  });
  rDec.addEventListener('change', function () {
    if (!rDec.checked) return;
    cMode = 2; cDecrypt = true;
    left.value = right.value; right.value = ''; key.value = '';
    rEnc.disabled = true;
  });
  $('c-default').addEventListener('click', function () {
    rEnc.disabled = false; rEnc.checked = true; rDec.disabled = true; rDec.checked = false;
    cMode = 1; cDecrypt = false;
    left.value = ''; right.value = ''; key.value = '';
  });
  $('c-copy').addEventListener('click', function () {
    if (!right.value) { toast('Belum ada hasil untuk disalin.'); return; }
    navigator.clipboard.writeText(right.value).then(
      function () { toast('Hasil disalin ke clipboard.'); },
      function () { right.select(); toast('Salin manual dengan Ctrl+C.'); }
    );
  });

  show('home');
})();
