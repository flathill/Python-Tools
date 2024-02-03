# -*- coding: utf-8 -*-
import sys
import re
from collections import defaultdict, OrderedDict

# 月名を月の番号にマッピング
month_to_number = {
    "Jan": '01', "Feb": '02', "Mar": '03', "Apr": '04', "May": '05', "Jun": '06',
    "Jul": '07', "Aug": '08', "Sep": '09', "Oct": '10', "Nov": '11', "Dec": '12'
}

def analyze_log(file_path):
    # 日付ごとにステータスの件数を集計する辞書
    daily_counts = defaultdict(lambda: defaultdict(int))

    # ログファイルを読み込む
    with open(file_path, 'r') as file:
        for line in file:
            # 月と日付のパターンを探す
            date_match = re.search(r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}', line)
            relay_match = re.search(r'relay=gmail-smtp-in.l.google.com', line)
            status_match = re.search(r'status=(\w+)', line)

            if date_match and relay_match and status_match:
                month, day = date_match.group().split()
                # 月名を月の番号に変換し、日付も2桁にフォーマット
                month_number = month_to_number[month]
                day_formatted = day.zfill(2)  # 日付を2桁にフォーマット
                date = "{} {}".format(month_number, day_formatted)  # ソート可能な形式に変換
                status = status_match.group(1)
                daily_counts[date][status] += 1

    # 日付をキーとしてソート
    sorted_daily_counts = OrderedDict(sorted(daily_counts.items(), key=lambda x: x[0]))

    # 集計結果を整形して表示
    print("Date       | Total | Details")
    print("-" * 40)  # 表のヘッダー
    for date, statuses in sorted_daily_counts.items():
        month_number, day = date.split()
        # 月の番号を月名に戻す、月名の取得時にはゼロパディングを考慮しない
        month_name = [name for name, num in month_to_number.items() if num == month_number][0]
        formatted_date = "{} {}".format(month_name, int(day))  # 日付の先頭のゼ ロを除去
        total = sum(statuses.values())
        details = ", ".join(["{}: {}".format(status, count) for status, count in statuses.items()])
        print("{:<10} | {:<5} | {}".format(formatted_date, total, details))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <path_to_log_file>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    analyze_log(log_file_path)
