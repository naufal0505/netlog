## NetLog Analyzer

**NetLog Analyzer** adalah toolkit analisis jaringan berbasis Python yang dirancang untuk membantu proses *network threat hunting* secara otomatis dari berbagai sumber data seperti file PCAP, Nmap, dan log sistem.

Tool ini mampu melakukan analisis mendalam terhadap lalu lintas jaringan dan menghasilkan insight keamanan seperti:

* Deteksi anomali jaringan
* Identifikasi aktivitas scanning
* Deteksi indikasi *command and control (C2)* seperti beaconing
* Klasifikasi risiko host
* Mapping ke MITRE ATT&CK framework

NetLog Analyzer sangat cocok digunakan untuk:

* Mahasiswa cybersecurity
* Network analyst
* Blue team / SOC analyst
* Digital forensics & incident response

---

## ✨ Fitur Utama

* 🔍 Analisis file PCAP (traffic inspection)
* 📊 Statistik jaringan lengkap (protocol, port, host, dll)
* 🚨 Deteksi ancaman otomatis:

  * Port scanning
  * Beaconing (C2 communication)
  * Suspicious traffic
* 🧠 Risk scoring & severity classification
* 🗺️ MITRE ATT&CK mapping
* 📈 Timeline serangan (attack timeline)
* 📁 Output laporan dalam format JSON

---

## 📊 Contoh Hasil Analisis

Tool ini mampu menghasilkan insight seperti:

* Total events: **1991**
* Risk level: **HIGH**
* Deteksi:

  * Port scanning dari host internal
  * Beaconing dengan interval stabil (indikasi C2)
* Top risky host:

  * `10.11.9.20` (HIGH risk)
* Mapping MITRE:

  * T1046 (Network Scanning)
  * T1071 (Application Layer Protocol)

(Sumber output CLI) 

---

## ⚙️ Instalasi

```bash
git clone https://github.com/username/netlog-analyzer.git
cd netlog-analyzer

pip install -r requirements.txt
```

---

## ▶️ Cara Menjalankan

Jalankan program utama:

```bash
python -m app.main
```

---

## 🧪 Cara Penggunaan

1. Jalankan aplikasi
2. Pilih jenis input:

   ```
   1. File Nmap
   2. File PCAP
   3. File Sistem Log Server
   ```
3. Masukkan path file, contoh:

   ```
   D:\path\to\file.pcapng
   ```
4. Tunggu proses analisis selesai
5. Hasil akan ditampilkan di terminal dan disimpan sebagai JSON

---

## 📁 Output

Hasil analisis akan disimpan dalam:

```
reports/pcap_report.json
```

Berisi:

* Network overview
* Top hosts & ports
* Threat detection
* Attack timeline
* Risk classification

---

## 🧠 Cara Kerja Singkat

1. Parsing file input (PCAP/Nmap/log)
2. Ekstraksi metadata jaringan
3. Analisis perilaku trafik:

   * Frequency analysis
   * Connection pattern
4. Deteksi anomali & threat pattern
5. Scoring risiko
6. Mapping ke MITRE ATT&CK
7. Generate report

---

## ⚠️ Threat Classification

Tool ini dapat mengidentifikasi kategori ancaman seperti:

* Reconnaissance (Scanning)
* Command & Control (Beaconing)
* Suspicious Internal Movement

Contoh:

> “Ditemukan pola koneksi periodik dengan interval stabil → indikasi beaconing (C2)” 

