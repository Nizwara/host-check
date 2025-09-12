### ✅ Cara Gunakan (Cuma 1 Perintah!)


# instal dependensi:

## Untuk Termux (Android)

### 1. Instal Termux dari F-Droid (bukan dari Play Store)
### 2. Update package dan 

```bash
pkg update
pkg install python git
pip install beautifulsoup4 requests
```


## Untuk VPS (Linux)

### 1. Update sistem dan instal dependensi:

```bash
sudo apt update
sudo apt install python3 python3-pip git
```

### 1. Instal modul Python yang diperlukan:

```bash
pip3 install beautifulsoup4 requests
```



  #  【𝐈𝐍𝐒𝐓𝐀𝐋𝐋 𝐒𝐂𝐑𝐈𝐏𝐓】

### 🔧 1. Simpan file `user-agents.txt` di folder yang sama  
Pastikan file ini ada dan berisi 1000+ user-agent seperti yang kamu punya.

### 📄 2. Simpan kode di atas sebagai `host.py`

```bash
nano host.py
```
Tempelkan kode → `Ctrl+O` → `Enter` → `Ctrl+X`

### 🔐 3. Beri izin eksekusi

```bash
chmod +x host.py
```

# Auto install
### Untuk Termux
```bash
pkg update -y && pkg install python git wget -y && mkdir -p ~/host-check && cd ~/host-check && wget https://raw.githubusercontent.com/Nizwara/host-check/main/host.py && wget https://raw.githubusercontent.com/Nizwara/host-check/main/user-agents.txt && pip install dnspython requests beautifulsoup4 && chmod +x host.py
```
### Untuk VPS
```bash
apt update -y && apt install python3 git wget -y && mkdir -p ~/host-check && cd ~/host-check && wget https://raw.githubusercontent.com/Nizwara/host-check/main/host.py && wget https://raw.githubusercontent.com/Nizwara/host-check/main/user-agents.txt && pip3 install dnspython requests beautifulsoup4 && chmod +x host.py
```


### 🚀 4. Jalankan!

#### ➤ Scan satu target:
```bash
./host.py -t example.com
```

#### ➤ Scan dengan proxy:
```bash
./host.py -t example.com -p http://127.0.0.1:8080
```

#### ➤ Ganti nama output:
```bash
./host.py -t example.com -o my-scan-result.txt
```./host.py -t vidio.com -o vidio.txt

#### ➤ Tanpa banner (untuk script otomatis):
```bash
./host.py -t example.com --no-banner
```

---

## 💡 Contoh Output (Terminal)

```
   __ __         __    ___                                
  / // /__  ___ / /_  / _ \___ ___ ___  ___  ___  ___ ___ 
 / _  / _ \(_-</ __/ / , _/ -_|_-</ _ \/ _ \/ _ \(_-</ -_)
/_//_/\___/___/\__/ /_/|_|\__/___/ .__/\___/_//_/___/\__/ 
                                /_/             V.2.9 CLI
    
         By : Killer-vpn
         Github : github.com/Nizwara
         Blog : www.nizwara.biz.id

[+] Target: example.com
[+] Output: results.txt
------------------------------------------------------------
[*] Using User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64...
[*] Starting scan for: example.com

[2024-06-15 10:30:15] Results for: example.com
============================================================
DNS Information:
  A: 93.184.216.34
  MX: 10 mail.example.com
  NS: ns1.example.com, ns2.example.com
  TXT: "v=spf1 include:spf.protection.outlook.com -all"

Subdomains Found (12):
  www.example.com
  api.example.com
  blog.example.com
  ...

HTTP Results:
  HTTPS:
    Status: 200
    Server: Apache
    X-Powered-By: PHP/8.1
    Response Time: 0.45s
    Redirects: 0
    Final URL: https://example.com/
  HTTP:
    Status: 301
    Server: nginx
    ...
============================================================

✅ Results saved to results.txt
```

### 📄 **Di `results.txt
```
[2024-06-18 21:00:00] Results for: vidio.com
============================================================
DNS Information:
  A: 103.224.212.222
  MX: mx1.vidio.com, mx2.vidio.com

--- FULL SUBDOMAIN LIST (for file export) ---
  livestreaming-google-etslive.int.vidio.com
  www-dsa.staging.vidio.com
  www.int.vidio.com
  gcp.staging.vidio.com
  tv-canary-vpn.vidio.com
  cdn-a.origin.dev.vidio.com
  app-etslive-2.vidio.com
  stickers.vidio.com
  airflow.vidio.com
  livestreaming-swiftserve-etslive.vidio.com
  ...
--- END FULL LIST ---

HTTP Results:
  HTTPS:
    Status: 200
    Server: nginx
    ...

Open Ports (3): 80, 443, 53

SSL Information:
  Version: TLSv1.3
  Cipher: TLS_AES_256_GCM_SHA384
  Subject: {...}
  Issuer: {...}

--- LEGACY FORMAT (v1.0 style: subdomain|ip|status|server|ports|protocol|) ---
  livestreaming-google-etslive.int.vidio.com|103.224.212.222|200|nginx|80,443|TLSv1.3|
  www-dsa.staging.vidio.com|103.224.212.222|200|cloudflare|80,443|TLSv1.2|
  ...
--- END LEGACY FORMAT ---
============================================================
```

---

## 🏆 Kelebihan Versi Ini

| Fitur | Status |
|-------|--------|
| ✅ Tidak ada menu — murni CLI | ✔️ |
| ✅ Auto-install semua library | ✔️ |
| ✅ Pakai **user-agents.txt** kamu (1000+) | ✔️ |
| ✅ Support proxy | ✔️ |
| ✅ Output rapi & bisa disimpan | ✔️ |
| ✅ Cocok untuk cron, automation, Docker, VPS | ✔️ |
| ✅ Tidak perlu interaksi | ✔️ |

---

## 📌 Bonus: Jalankan Secara Otomatis Setiap Jam (Cron Job)

Buka editor cron:

```bash
crontab -e
```

Tambahkan baris ini untuk scan `example.com` tiap jam:

```bash
0 * * * * cd /path/to/script && ./host.py -t example.com -o /path/to/results.txt >> /var/log/host-cli.log 2>&1
```

---

