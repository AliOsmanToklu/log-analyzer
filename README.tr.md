# log-analyzer

[![CI](https://github.com/AliOsmanToklu/log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/AliOsmanToklu/log-analyzer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[English](README.md)

Kimlik doğrulama loglarında saldırı izlerini arayan bir komut satırı aracı. Şunları tespit eder:
kısa sürede yoğun brute force denemeleri, bunların ardından gelen başarılı girişler ve yavaş kullanıcı adı taramaları.
**Linux SSH loglarını** (`/var/log/auth.log`) ve CSV'ye aktarılmış **Windows oturum açma olaylarını** okur,
ikisini tipli tek bir olay modeline çevirir ve aynı dedektörlerden geçirir.

- Çalışma zamanında yalnızca Python standart kütüphanesi; tamamen tip kontrollü (`mypy --strict`)
- %100 test kapsamı; Linux ve Windows üzerinde Python 3.11–3.14 için CI
- Tablolar için CSV rapor, diğer araçlar için JSON rapor

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

`--output report.json` ile zaman damgaları ve kullanılan parametreler dahil tüm ayrıntıları içeren
bir JSON rapor yazılır; örneği [İngilizce README](README.md#example)'de.

## Kurulum

Python 3.11+ gerekir.

```bash
git clone https://github.com/AliOsmanToklu/log-analyzer.git
cd log-analyzer
python -m venv .venv
.venv\Scripts\activate           # Linux/macOS: source .venv/bin/activate
pip install -e .
```

## Kullanım

```bash
log-analyzer <dosya> [seçenekler]
```

| Seçenek | Varsayılan | Anlamı |
|---|---|---|
| `dosya` | — | Analiz edilecek log |
| `--format {auto,ssh,windows}` | `auto` | `auto`: `.csv` → Windows dışa aktarımı, diğerleri → SSH auth logu |
| `--threshold N` | `10` | Bir pencere içinde brute force sayılacak başarısız deneme sayısı |
| `--window SANIYE` | `60` | Kayan pencere süresi |
| `--scan-threshold N` | `3` | Tek IP'den yavaş tarama sayılacak geçersiz kullanıcı denemesi sayısı |
| `--year YIL` | tahmin | Yıl bilgisi içermeyen klasik syslog zaman damgaları için yıl |
| `--output YOL` | `report.csv` | Rapor yolu; `.json` → JSON, diğerleri → CSV (üzerine yazılır) |

Başarıda çıkış kodu `0`, hatalı argüman veya okunamayan girdide `2`'dir; hata stderr'e tek satır olarak yazılır.

### Desteklenen SSH satırları

`Failed <yöntem> for [invalid user] <kullanıcı> from <ip>` → başarısız,
`Accepted <yöntem> for <kullanıcı> from <ip>` → başarılı,
`Invalid user <kullanıcı> from <ip>` → geçersiz kullanıcı.
`<yöntem>` herhangi bir doğrulama yöntemi olabilir (`password`, `publickey`, `keyboard-interactive/pam`, ...).

Klasik (`Oct 25 11:02:05`) ve RFC 3339 (`2026-10-25T11:02:05.123+03:00`) zaman damgaları okunur.
Klasik biçimde yıl olmadığı için yıl, log gelecekte bitmeyecek şekilde tahmin edilir ve Aralık → Ocak geçişleri izlenir.
rsyslog'un `message repeated N times: [ ... ]` satırları N olay olarak sayılır.

Windows olaylarını dışa aktarmak için gereken PowerShell komutu [İngilizce README](README.md#exporting-windows-logon-events)'de yer alır.

## Tespit Kuralları

| Tespit | Önem | Kural |
|---|---|---|
| `BRUTE_FORCE` | HIGH | Bir IP, herhangi bir `window` saniyelik aralıkta ≥ `threshold` başarısız giriş yapmışsa (sıralı denemeler üzerinde iki işaretçili kayan pencere) |
| `POSSIBLE_COMPROMISE` | CRITICAL | Brute force yapan IP sonradan başarılı giriş yapmışsa |
| `SLOW_SCAN` | MEDIUM | Bir IP, zamandan bağımsız olarak ≥ `scan-threshold` kez var olmayan kullanıcı adı denemişse (yalnızca SSH) |

## Mimari

Ayrıştırma (`parsers/`), tespit (`detectors.py`, `analysis.py`) ve çıktı (`cli.py`, `report.py`) ayrı katmanlardır.
Bu sayede aynı `analyze()` çağrısı, tespit koduna dokunmadan bir web API gibi başka arayüzlerde de kullanılabilir.
Ayrıntılı modül yapısı [İngilizce README](README.md#architecture)'de.

## Geliştirme

```bash
pip install -e ".[dev]"
pytest --cov          # testler ve kapsam
ruff format .         # biçimlendirme
ruff check .          # lint
mypy                  # tip kontrolü (strict)
```

CI aynı kontrolleri her push ve pull request'te çalıştırır.

`samples/` klasöründe bilinen bir saldırı senaryosu içeren sentetik loglar bulunur:

```bash
python scripts/generate_ssh_log.py        # -> samples/auth.log
python scripts/generate_windows_log.py    # -> samples/windows_events.csv
```

## Lisans

[MIT](LICENSE)
