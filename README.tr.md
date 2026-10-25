# log-analyzer

[![CI](https://github.com/AliOsmanToklu/log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/AliOsmanToklu/log-analyzer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[English](README.md)

Kimlik doğrulama loglarında saldırı izlerini arar: kısa sürede yoğun brute force denemeleri,
bunların ardından gelen başarılı girişler ve yavaş kullanıcı adı taramaları.
**Linux SSH loglarını** (`/var/log/auth.log`) ve CSV'ye aktarılmış **Windows oturum açma olaylarını** okur,
ikisini tipli tek bir olay modeline çevirir ve aynı dedektörlerden geçirir. **Komut satırı aracı** ve
**REST API** olarak kullanılabilir.

- **CLI**: yalnızca standart kütüphane; tablolar için CSV, diğer araçlar için JSON rapor
- **REST API**: FastAPI, arka planda analiz, PostgreSQL veya SQLite'ta saklanan ve tüm yüklemeler
  arasında aranabilen bulgular, OpenAPI dokümanı, Docker Compose
- Tamamen tip kontrollü (`mypy --strict`), %99 dal kapsamı; Linux/Windows'ta Python 3.11–3.14,
  PostgreSQL ve Docker imajı için CI

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
pip install -e .                 # yalnızca CLI, bağımlılık yok
pip install -e ".[api]"          # REST API ile birlikte (PostgreSQL için ",postgres" ekleyin)
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

## REST API

Docker ile (API + PostgreSQL):

```bash
docker compose up --build
# Swagger arayüzü: http://localhost:8000/docs
```

Ya da yerelde SQLite ile:

```bash
pip install -e ".[api]"
log-analyzer-api serve          # veritabanını migrate eder, 127.0.0.1:8000'de çalışır
```

| Metot | Yol | Açıklama |
|---|---|---|
| `POST` | `/analyses` | Log yükle (multipart `file`; isteğe bağlı `format`, `threshold`, `window_seconds`, `scan_threshold`, `year`). Hemen `202 Accepted` ve `Location` başlığı döner; analiz arka planda çalışır |
| `GET` | `/analyses` | Analizleri yeniden eskiye listele (`limit`, `offset`, `status`) |
| `GET` | `/analyses/{id}` | Bir analizin durumu, parametreleri ve tüm bulguları |
| `DELETE` | `/analyses/{id}` | Analizi ve bulgularını sil |
| `GET` | `/findings` | Tüm analizlerde bulgu ara (`ip`, `severity`, `detection`, `limit`, `offset`) |
| `GET` | `/health` | Canlılık ve veritabanı kontrolü (veritabanına ulaşılamazsa `503`) |

Hatalar standart durum kodlarıyla döner: `404` bilinmeyen id, `413` boyut sınırını aşan yükleme,
`422` geçersiz parametre. Ayrıştırılamayan bir log da `202` alır; analiz `status: "failed"` ve bir `error` ile biter.

Yapılandırma: `LOG_ANALYZER_DATABASE_URL` (varsayılan `sqlite:///log_analyzer.db`) ve
`LOG_ANALYZER_MAX_UPLOAD_MB` (varsayılan `20`). `curl` örnekleri [İngilizce README](README.md#example-1)'de.

## Tespit Kuralları

| Tespit | Önem | Kural |
|---|---|---|
| `BRUTE_FORCE` | HIGH | Bir IP, herhangi bir `window` saniyelik aralıkta ≥ `threshold` başarısız giriş yapmışsa (sıralı denemeler üzerinde iki işaretçili kayan pencere) |
| `POSSIBLE_COMPROMISE` | CRITICAL | Brute force yapan IP sonradan başarılı giriş yapmışsa |
| `SLOW_SCAN` | MEDIUM | Bir IP, zamandan bağımsız olarak ≥ `scan-threshold` kez var olmayan kullanıcı adı denemişse (yalnızca SSH) |

## Mimari

Ayrıştırma (`parsers/`), tespit (`detectors.py`, `analysis.py`) ve çıktı (`cli.py`, `report.py`, `api/`) ayrı katmanlardır.
CLI ve API aynı `analyze()` çağrısını kullanır. Ayrıntılı modül yapısı [İngilizce README](README.md#architecture)'de.

### Tasarım kararları

- **Tek tespit çekirdeği, iki arayüz.** HTTP route'ları yalnızca istekleri `api.service` çağrılarına çevirir.
- **CLI bağımlılıksız kalır.** Web, veritabanı ve migration kütüphaneleri isteğe bağlı `api` ekindedir.
- **Asenkron sözleşme.** `POST /analyses` hemen `202` döner, istemci kaynağı sorgular. İş bugün FastAPI
  arka plan görevlerinde çalışır; aynı sözleşme ileride istemcileri değiştirmeden bir kuyruk işçisine taşınabilir.
  Arka plan hatası bir analizi asla `pending`'de bırakmaz.
- **Bulgular ayrıca satır olarak saklanır.** IP ve önem derecesine göre indeksli olduğundan
  "bu IP başka bir yerde görüldü mü?" tek bir SQL sorgusudur.
- **Yüklenen loglar saklanmaz.** Loglar kullanıcı adı ve adres içerir; yalnızca bulgular tutulur.
- **Şema değişiklikleri migration ile yapılır.** Alembic migration'ları paketle gelir (Docker imajı açılışta
  kendini migrate eder); modeller ile migration'lar uyuşmazsa bir test başarısız olur.
- **Zaman damgaları her zaman UTC ve ofsetlidir**; zaman dilimi tutmayan SQLite'ta bile.

## Geliştirme

```bash
pip install -e ".[dev]"
pytest --cov          # testler ve kapsam
ruff format .         # biçimlendirme
ruff check .          # lint
mypy                  # tip kontrolü (strict)
```

API testlerini SQLite yerine PostgreSQL'e karşı çalıştırmak için `LOG_ANALYZER_TEST_DATABASE_URL`
verin (o veritabanının tabloları silinir!); ayrıntılar [İngilizce README](README.md#development)'de.

CI lint ve tip kontrollerini, Python 3.11–3.14 (Linux) ve 3.14 (Windows) testlerini, PostgreSQL'e karşı
API testlerini çalıştırır; Docker imajını da derleyip dener.

`samples/` klasöründe bilinen bir saldırı senaryosu içeren sentetik loglar bulunur:

```bash
python scripts/generate_ssh_log.py        # -> samples/auth.log
python scripts/generate_windows_log.py    # -> samples/windows_events.csv
```

## Lisans

[MIT](LICENSE)
