import argparse
import csv

from parser import parse_file
from detector import detect_bruteforce, detect_compromise, detect_scanners
from windows_parser import parse_windows_csv

def main():
    ap = argparse.ArgumentParser(description="SSH log analiz aracı")
    ap.add_argument('file', help="Analiz edilecek log dosyası")
    ap.add_argument('--threshold', type=int, default=10,
                    help="Brute force için başarısız deneme eşiği (varsayılan: 10)")
    ap.add_argument('--window', type=int, default=60,
                    help="Pencere süresi, saniye (varsayılan: 60)")
    ap.add_argument('--output', default='rapor.csv', help="CSV rapor dosyası")
    args = ap.parse_args()

    if args.file.lower().endswith('.csv'):
        events = parse_windows_csv(args.file)
    else:
        events = parse_file(args.file)
    print(f"=== Log Analizi: {args.file} ===")
    print(f"Toplam olay: {len(events)}\n")

    suspects = detect_bruteforce(events, args.threshold, args.window)
    compromised = detect_compromise(events, suspects)
    scanners = detect_scanners(events)

    rows = []

    print("--- Brute Force Şüphelileri ---")
    if not suspects:
        print("Bulunamadı.")
    for ip, info in suspects.items():
        print(f"[!] {ip}: {info['total_failed']} başarısız deneme "
              f"({args.window} sn içinde en fazla {info['max_in_window']})")
        print(f"    Denenen kullanıcılar: {', '.join(info['users_tried'])}")
        rows.append([ip, 'BRUTE_FORCE', 'YÜKSEK',
                     f"{info['total_failed']} başarısız deneme"])

    print("\n--- KRİTİK: Brute Force Sonrası Başarılı Giriş ---")
    if not compromised:
        print("Bulunamadı.")
    for e in compromised:
        print(f"[!!!] {e['ip']} -> '{e['user']}' kullanıcısıyla giriş yaptı ({e['time']})")
        rows.append([e['ip'], 'OLASI_ELE_GEÇİRME', 'KRİTİK',
                     f"{e['user']} kullanıcısıyla başarılı giriş"])

    print("\n--- Yavaş Tarama Şüphelileri ---")
    if not scanners:
        print("Bulunamadı.")
    for ip, info in scanners.items():
        print(f"[!] {ip}: {info['count']} geçersiz kullanıcı denemesi "
              f"({', '.join(info['users_tried'])})")
        rows.append([ip, 'YAVAŞ_TARAMA', 'ORTA',
                     f"{info['count']} geçersiz kullanıcı denemesi"])

    with open(args.output, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'Tespit', 'Önem', 'Detay'])
        writer.writerows(rows)

    print(f"\nRapor kaydedildi: {args.output}")


if __name__ == '__main__':
    main()