# OBSERV AGENT

*Live AI observatory untuk Robinhood Chain.*

OBSERV AGENT memantau setiap token baru dari banyak launchpad, menilai sinyal bahayanya dengan bukti on-chain, membuat **Genesis Certificate** untuk tiap token, dan menyediakan AI agent yang menjawab pertanyaan berdasarkan data live.

- **Server Node 18+ tanpa dependensi.** Satu service menyajikan web, JSON API, SSE live, dan endpoint AI.
- **Sumber data:**
  - [DexPaprika](https://dexpaprika.com): pool, harga, volume, likuiditas.
  - **RPC Robinhood Chain**: scanner launchpad, holder, wallet pembuat, swap test, dan decoder transaksi.
- Lapisan data (scanner launchpad, swap test, client DexPaprika) diadaptasi dari [FISHY](https://github.com/oxhoodey/fishy).

## Arsitektur

```
Railway (1 service)
└── server.js
    ├── lib/launchpads.js  scanner on-chain: Pons V2 (TokenLaunched + CurveBuy/Sell), Flap (vanity 8888/7777),
    │                      hood.fun, LaunchHood, Virtuals, Klik, Doppler, Ape.store, Bags, Clanker, pools.trade, trench
    ├── lib/threat.js      threat scanner: holder, wallet pembuat, bundled buys, impersonation, swap test
    ├── lib/swaptest.js    simulasi beli → jual lewat quoter Uniswap V2/V3/V4 (read-only)
    ├── lib/ai.js          AI agent core (provider bebas: Groq / Gemini / OpenRouter / OpenAI / Anthropic) + tools
    ├── lib/registry.js    daftar chain (Elysium, Base, …) dan info tiap launchpad
    └── public/index.html  UI Ink Edition (Three.js + GSAP + shader GLSL)
```

## Deploy: GitHub → Railway

### 1. Repo GitHub
Buat repo kosong `tradepadrh/observagent`, lalu dari Git Bash:
```bash
bash push.sh "OBSERV v1"            # push ke branch dev
bash push.sh "OBSERV v1" main       # push ke branch main (production)
```
`push.sh` mengambil `observ*.zip` terbaru dari folder Downloads, menimpa isi repo lokal, lalu commit dan push. File `.env` tidak ikut ter-upload.

### 2. Railway: environment dev dan production
1. Buka **New Project → Deploy from GitHub repo**, lalu pilih `observ`. Railway membaca `railway.json` (start `node server.js`, healthcheck `/api/health`).
2. Buka **Settings → Environments**. Environment `production` diarahkan ke branch `main`. Tambahkan environment **`dev`**, lalu di service-nya buka **Settings → Source → Branch: `dev`**.
3. Di tiap environment, buka **Settings → Networking → Generate Domain**.
4. Buka **Variables**, lalu isi dari `.env.example`. Railway otomatis redeploy setiap variabel berubah.

`PORT` jangan diisi, karena Railway mengisinya sendiri.

### 3. Variabel penting

| Variabel | Keterangan |
|---|---|
| `SITE_URL` | Domain Railway/domainmu. Dipakai Agent Kit sebagai base URL API publik. |
| `TOKEN_CA` | Alamat kontrak token kalian. Kalau kosong, strip CA menampilkan **PRE-LAUNCH**. Saat launch cukup isi ini, tanpa rebuild. |
| `TOKEN_TICKER`, `PROJECT_NAME`, `LAUNCHPAD_NAME`, `LAUNCHPAD_URL` | Identitas token. |
| `PROJECT_X`, `DEV_NAME`, `DEV_X`, `DEV_ROLE`, `DEV_BIO`, `TELEGRAM_URL`, `WEBSITE_URL` | Panel **TOKEN · DEV**. |
| `AI_API_KEY` | Mengaktifkan AI agent. Provider dideteksi dari awalan key: `gsk_…` Groq (gratis), `AIza…` Gemini (gratis), `sk-or-…` OpenRouter, `sk-ant-…` Anthropic. Kosong = skrip lokal di atas data live. |
| `AI_MODEL` | Opsional. Default Groq `openai/gpt-oss-120b`, Gemini `gemini-flash-latest`. |
| `AI_PROVIDER` / `AI_BASE_URL` | Opsional, untuk provider lain yang kompatibel OpenAI. |
| `AI_DEBUG_ERRORS` | `1` = tampilkan alasan error di web (untuk debug). Default: pengunjung otomatis dapat jawaban mode lokal, alasan hanya di log Railway (`agent-core:`). |
| `AI_PER_IP_PER_MINUTE`, `AI_DAILY_LIMIT` | Batas biaya AI (default 6/menit per IP, 800/hari). |
| `RPC_URL` | **Sangat disarankan pakai RPC privat** (Alchemy/Chainstack/QuickNode), karena scanner banyak memakai `eth_getLogs`. |
| `DEXPAPRIKA_API_KEY` | Opsional. Free key menaikkan limit. |
| `LAUNCHPADS_JSON` | Menambah launchpad tanpa ubah kode, misalnya `[{"key":"fobo","name":"FOBO","addrs":["0x…"]}]` |
| `CHAINS_JSON`, `PAD_INFO_JSON` | Override daftar chain atau info launchpad di UI. |

Daftar lengkap dengan default ada di `.env.example`.

### 4. Cek setelah deploy
- `/api/health` harus menunjukkan `ok: true`, `pools > 0`, dan `scanner.tracked` yang naik seiring waktu.
- Indikator di kanan header berubah dari **ESTABLISHING UPLINK…** menjadi **LIVE · ROBINHOOD CHAIN 4663**.
- Kalau `scanner.lastError` berisi pesan soal range atau limit, berarti RPC publik membatasi `eth_getLogs`. Ganti `RPC_URL` ke RPC privat.

## API publik (read-only, dipakai UI dan Agent Kit)

| Endpoint | Isi |
|---|---|
| `GET /api/state` | Snapshot awal UI: stats, market, feed, token terbaru |
| `GET /api/stream` | SSE: `event`, `stats`, `market`, `scan` |
| `GET /api/stats?window=300` | Telemetri: blok, gas, tx/s, launch per launchpad, pool baru, graduation, flag ancaman, equity flow |
| `GET /api/feed`, `GET /api/tokens` | Event terbaru, token terbaru dari scanner |
| `GET /api/genesis/{ca}` | Genesis Certificate: data launch, pool DEX, threat scan lengkap |
| `GET /api/threat/{ca}` | Threat scan (`?fresh=1` untuk scan ulang) |
| `GET /api/radar?pad=pons` | Token yang sudah di-scan, diurutkan dari skor tertinggi |
| `GET /api/tx/{hash}` | Decode transaksi: method, status, fee, transfer token |
| `GET /api/coverage`, `/api/daily`, `/api/project`, `/api/kit/context` | Coverage, The 4663 Daily, info token resmi, Context Pack |
| `POST /api/ask` `{q, history}` | AI agent (kalau `AI_API_KEY` diisi) |

Endpoint berat (genesis, threat, tx, swaptest) dibatasi `HEAVY_PER_IP_PER_MINUTE` per IP.

## Threat scanner: sinyal dan bobot

| Sinyal | Bobot | Sumber |
|---|---|---|
| SELL BLOCKED | 40 | Swap test: hasil round trip ≤ 50% (`NO EXIT` / `HOOK TRAP`) |
| IMPERSONATES THIS PROJECT | 30 | Memakai ticker atau nama project ini, tapi bukan `TOKEN_CA` |
| CREATOR EXIT | 25 | Wallet pembuat sudah memindahkan ≥ 50% dari posisi puncaknya |
| CREATOR CONCENTRATION | 20 | Pembuat memegang > 10% supply |
| BUNDLED GENESIS | 20 | ≥ 5 wallet menerima token dalam 2 blok pertama |
| TOP-10 CONCENTRATION | 15 | 10 wallet teratas (bukan kontrak atau pool) memegang > 45% supply |
| SERIAL LAUNCHER | 15 | Pembuat yang sama meluncurkan ≥ 3 token lain selama dipantau |
| TICKER IMPERSONATION / CLONE TICKER | 10–15 | Meniru ticker saham atau brand, atau memakai ticker yang sama dengan token lain yang jauh lebih dalam likuiditasnya |
| HOOK TAX | 15 | Swap test: hook v4 mengambil biaya di atas fee normal |
| CUSTOM HOOK LOGIC | 10 | Hook v4 punya izin `beforeSwap` atau `*ReturnsDelta` |
| THIN EXIT | 10 | Kurang dari $2.000 bisa dijual sebelum harga turun 5% |
| INFLATED VOLUME | 10 | Kurang dari 50% volume 24 jam masuk akal untuk likuiditasnya |

Skor adalah jumlah bobot (maksimal 100), dengan level LOW < 25 ≤ ELEVATED < 50 ≤ HIGH < 75 ≤ CRITICAL. Setiap sinyal membawa bukti. **Ini sinyal heuristik, bukan vonis**: UI dan AI selalu menyebutnya begitu, dan tidak pernah memakai kata "scam". Pemeriksaan yang tidak bisa dijalankan tercantum di bagian *Not evaluated*.

## Yang perlu diketahui

- **State di memori.** Feed, Daily, dan cache threat akan kosong lagi setiap kali server restart atau redeploy. Untuk histori permanen, tambahkan Railway Postgres (masuk roadmap).
- **Equity flow** = kenaikan volume 24 jam pool stock token sejak refresh sebelumnya. Angka ini batas bawah aktivitas baru, bukan daftar swap satu per satu (stream swap DexPaprika butuh paket berbayar).
- **FOBO dan Ascend (Elysium)** masih tampil sebagai *standby* sampai alamat kontraknya ditambahkan lewat `LAUNCHPADS_JSON`.
- **Holder count** untuk token yang lebih tua dari `THREAT_MAX_BLOCKS` adalah batas bawah (ditandai `≥`).
- **Atribusi:** penggunaan komersial data DexPaprika mensyaratkan link atribusi. Link ini sudah ada di bar narator.

## Jalankan lokal
```bash
node server.js          # http://localhost:8787
```
