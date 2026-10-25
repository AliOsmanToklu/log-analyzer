# log-analyzer

[English](README.md)

Kimlik doğrulama loglarında saldırı izlerini arayan bir komut satırı aracı. Şunları tespit eder:
kısa sürede yoğun brute force denemeleri, bunların ardından gelen başarılı girişler ve yavaş kullanıcı adı taramaları.
**Linux SSH loglarını** (`/var/log/auth.log`) ve CSV'ye aktarılmış **Windows oturum açma olaylarını** okur,
ikisini ortak bir olay formatına çevirir ve aynı dedektörlerden geçirir.

Yalnızca Python standart kütüphanesi kullanılır; çalışma zamanı bağımlılığı yoktur.

## Örnek

```console
$ log-analyzer samples/auth.log
=== Log Analysis: samples/auth.log ===
Total events: 66

--- Brute Force Suspects ---
[!] 203.0.113.45: 40 failed attempts (max 21 within 60s)
    Users tried: admin, ahmet, root, test, ubuntu

--- CRITICAL: Successful Login After Brute Force ---
[!!!] 203.0.113.45 -> logged in as 'ahmet' (2026-10-25 11:02:05)

--- Slow Scan Suspects ---
[!] 198.51.100.7: 6 invalid user attempts (oracle)

Report saved: report.csv
```

## Kurulum

Python 3.10+ gerekir.

```bash
git clone https://github.com/<kullanici-adiniz>/log-analyzer.git
cd log-analyzer
python -m venv .venv
.venv\Scripts\activate           # Linux/macOS: source .venv/bin/activate
pip install -e .
```

## Kullanım

```bash
log-analyzer <dosya> [--threshold N] [--window SANIYE] [--output report.csv]
```

| Seçenek | Varsayılan | Anlamı |
|---|---|---|
| `dosya` | — | Analiz edilecek log. `.csv` → Windows dışa aktarımı, diğerleri → SSH auth logu |
| `--threshold` | `10` | Bir pencere içinde brute force sayılacak başarısız deneme sayısı |
| `--window` | `60` | Kayan pencere süresi (saniye) |
| `--output` | `report.csv` | CSV raporun yazılacağı yol (üzerine yazılır) |

Windows olaylarını dışa aktarmak için gereken PowerShell komutu [İngilizce README](README.md#exporting-windows-logon-events)'de yer alır.

## Tespit Kuralları

| Tespit | Önem | Kural |
|---|---|---|
| `BRUTE_FORCE` | HIGH | Bir IP, herhangi bir `window` saniyelik aralıkta ≥ `threshold` başarısız giriş yapmışsa (sıralı denemeler üzerinde iki işaretçili kayan pencere) |
| `POSSIBLE_COMPROMISE` | CRITICAL | Brute force yapan IP sonradan başarılı giriş yapmışsa |
| `SLOW_SCAN` | MEDIUM | Bir IP, zamandan bağımsız olarak ≥ 3 kez var olmayan kullanıcı adı denemişse (yalnızca SSH) |

## Örnek Veri

`samples/` klasöründe bilinen bir saldırı senaryosu içeren sentetik loglar bulunur:

```bash
python scripts/generate_ssh_log.py        # -> samples/auth.log
python scripts/generate_windows_log.py    # -> samples/windows_events.csv
```

## Lisans

[MIT](LICENSE)
