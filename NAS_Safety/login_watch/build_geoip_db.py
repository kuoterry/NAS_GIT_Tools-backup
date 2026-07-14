"""
把 MaxMind GeoLite2-City-CSV 轉成 login_watch.py 查詢用的本機 sqlite 資料庫。

用法（在 NAS 上執行，只需在第一次部署、或要更新 GeoLite2 資料時執行一次）：
    python3 build_geoip_db.py [geoip_src 目錄路徑] [輸出的 geoip.sqlite3 路徑]

輸入需求：
    geoip_src 目錄下需放置從 MaxMind 免費帳號下載的 GeoLite2-City-CSV 版本，
    至少要有 GeoLite2-City-Blocks-IPv4.csv 與 GeoLite2-City-Locations-en.csv 兩個檔案。
    目前只處理 IPv4 網段，IPv6 不在範圍內。
"""

import csv
import ipaddress
import sqlite3
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_SRC_DIR = SCRIPT_DIR / "geoip_src"
DEFAULT_DB_PATH = SCRIPT_DIR / "geoip.sqlite3"


def load_locations(locations_csv_path):
    """
    讀取 GeoLite2-City-Locations-en.csv，建立 geoname_id 對應到「國家、城市」的字典。

    參數:
        locations_csv_path (Path): GeoLite2-City-Locations-en.csv 的路徑。

    依賴: 標準庫 csv。

    回傳:
        dict[str, tuple[str, str]]: geoname_id -> (country_name, city_name)。
    """
    locations = {}
    with open(locations_csv_path, "r", encoding="utf-8") as locations_file:
        reader = csv.DictReader(locations_file)
        for row in reader:
            locations[row["geoname_id"]] = (row.get("country_name", ""), row.get("city_name", ""))
    return locations


def build_database(blocks_csv_path, locations_csv_path, output_db_path):
    """
    讀取 IPv4 網段 CSV 與地點對照 CSV，寫入一個以網段起始位址排序、可用範圍查詢的 sqlite 資料庫。

    參數:
        blocks_csv_path (Path): GeoLite2-City-Blocks-IPv4.csv 的路徑。
        locations_csv_path (Path): GeoLite2-City-Locations-en.csv 的路徑。
        output_db_path (Path): 輸出的 geoip.sqlite3 路徑，若已存在會被覆蓋重建。

    依賴: 標準庫 csv、ipaddress、sqlite3；load_locations()。

    回傳:
        int: 寫入的網段筆數。
    """
    locations = load_locations(locations_csv_path)

    if output_db_path.exists():
        output_db_path.unlink()

    connection = sqlite3.connect(output_db_path)
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE ranges (
                start_int INTEGER NOT NULL,
                end_int INTEGER NOT NULL,
                country TEXT,
                city TEXT
            )
            """
        )

        inserted_count = 0
        batch = []
        with open(blocks_csv_path, "r", encoding="utf-8") as blocks_file:
            reader = csv.DictReader(blocks_file)
            for row in reader:
                network_text = row["network"]
                geoname_id = row.get("geoname_id") or row.get("registered_country_geoname_id")
                country, city = locations.get(geoname_id, ("", ""))

                network = ipaddress.ip_network(network_text)
                batch.append((int(network[0]), int(network[-1]), country, city))
                inserted_count += 1

                if len(batch) >= 5000:
                    cursor.executemany(
                        "INSERT INTO ranges (start_int, end_int, country, city) VALUES (?, ?, ?, ?)",
                        batch,
                    )
                    batch.clear()

        if batch:
            cursor.executemany(
                "INSERT INTO ranges (start_int, end_int, country, city) VALUES (?, ?, ?, ?)",
                batch,
            )

        cursor.execute("CREATE INDEX idx_ranges_start ON ranges (start_int)")
        connection.commit()
        return inserted_count
    finally:
        connection.close()


def main():
    """
    命令列進入點：解析參數並呼叫 build_database()。

    參數: 無（透過 sys.argv 可選擇指定 geoip_src 目錄與輸出資料庫路徑，皆有預設值）。

    依賴: build_database()。

    回傳:
        None（找不到輸入檔時以 sys.exit(1) 結束）。
    """
    src_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SRC_DIR
    output_db_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_DB_PATH

    blocks_csv_path = src_dir / "GeoLite2-City-Blocks-IPv4.csv"
    locations_csv_path = src_dir / "GeoLite2-City-Locations-en.csv"

    if not blocks_csv_path.exists() or not locations_csv_path.exists():
        print(f"錯誤: 在 {src_dir} 找不到 GeoLite2-City-Blocks-IPv4.csv 或 GeoLite2-City-Locations-en.csv", file=sys.stderr)
        sys.exit(1)

    inserted_count = build_database(blocks_csv_path, locations_csv_path, output_db_path)
    print(f"完成，共寫入 {inserted_count} 筆 IPv4 網段到 {output_db_path}")


if __name__ == "__main__":
    main()
