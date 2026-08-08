# Proxy HTTP Checker

Tool Go untuk memeriksa kesehatan daftar proxy (HTTP, SOCKS4, SOCKS5) dari file CSV, mengukur latency, lalu menulis laporan hasil ke file teks di folder root.

## Cara Kerja

1. Baca daftar proxy dari `proxy_gabungan_final.csv`.
2. Setiap proxy dicek secara paralel (50 worker) dengan melakukan request ke endpoint uji:
   - `https://1.1.1.1/cdn-cgi/trace`
   - `http://checkip.amazonaws.com/`
3. Proxy dianggap **alive** jika berhasil mendapat respons valid dari salah satu endpoint.
4. Latency diukur dari waktu mulai request sampai respons berhasil dibaca.
5. Hasil ditulis ke dua file:

| File | Isi |
|------|-----|
| `proxy_health.txt` | Laporan detail, hanya proxy yang **alive**, diurutkan dari latency terkecil |
| `proxy_alive.txt` | Daftar proxy hidup dalam format `ip:port (tipe) \| latency`, diurutkan dari latency terkecil |

## Format CSV Input

File `proxy_gabungan_final.csv` berformat:

```csv
type,ip,port,GeoIP
http,38.211.24.146,8080,ID
socks5,1.2.3.4,1080,US
socks4,5.6.7.8,4145,JP
```

| Kolom | Keterangan |
|-------|------------|
| `type` | Tipe proxy: `http`, `https`, `socks5`, atau `socks4` |
| `ip` | Alamat IP proxy |
| `port` | Port proxy |
| `GeoIP` | Kode negara (hanya untuk pelaporan) |

## Cara Menjalankan

```bash
go run main.go
```

Hasilnya muncul di console sekaligus ditulis ke `proxy_health.txt` dan `proxy_alive.txt` di folder yang sama.

## GitHub Actions

Folder `.github/workflows/action.yml` berisi workflow yang otomatis:

- Menjalankan `main.go` di runner Ubuntu
- **Jadwal**: setiap hari 03:07 UTC (`schedule`), bisa juga di-trigger manual lewat tab **Actions** → **Run workflow**, atau setiap ada `push` ke branch `main`
- Hasil (`proxy_health.txt`, `proxy_alive.txt`) di-upload sebagai artifact bernama `proxy-results`, bisa diunduh dari halaman workflow run

## Catatan

- Proxy SOCKS4 diimplementasikan native tanpa dependency eksternal.
- SOCKS5 memakai `golang.org/x/net/proxy`.
- Proxy HTTPS dianggap sebagai proxy HTTP biasa dengan koneksi melalui host/port yang diberikan.
