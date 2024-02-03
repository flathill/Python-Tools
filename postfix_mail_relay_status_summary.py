# -*- coding: utf-8 -*-
import sys
import re
from collections import defaultdict, OrderedDict

# 月名を月の番号にマッピング（2桁フォーマット）
month_to_number = {
    "Jan": '01', "Feb": '02', "Mar": '03', "Apr": '04', "May": '05', "Jun": '06',
    "Jul": '07', "Aug": '08', "Sep": '09', "Oct": '10', "Nov": '11', "Dec": '12'
}

# ホスト名の正規表現パターン（aspmxのパターンを含む）
relay_hosts_patterns = [
    r"gmail-smtp-in\.l\.google\.com",
    r"alt[1-4]\.aspmx\.l\.google\.com",  # aspmxの文字列にマッチするパターンを追加
    # 他の正規表現パターンを追加可能
]

def find_matching_relay(line, relay_hosts_patterns):
    for pattern in relay_hosts_patterns:
        if re.search(r'relay=' + pattern, line):
            return pattern
    return None

def analyze_log(file_path):
    # ホスト名ごと、そして日付ごとにステータスの件数を集計する辞書
    analysis_results = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

    with open(file_path, 'r') as file:
        for line in file:
            date_match = re.search(r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}', line)
            relay_match = find_matching_relay(line, relay_hosts_patterns)
            status_match = re.search(r'status=(\w+)', line)

            if date_match and relay_match and status_match:
                month, day = date_match.group().split()
                month_number = month_to_number[month]
                day_formatted = day.zfill(2)  # 日付を2桁にフォーマット
                date = "{} {}".format(month_number, day_formatted)  # 月日を2桁で統一
                status = status_match.group(1)
                # マッチングしたホスト名で結果を記録
                analysis_results[relay_match][date][status] += 1

    # ホスト名ごとに結果を出力
    for relay_pattern, daily_data in analysis_results.items():
        print("Analysis for relay matching pattern: {}".format(relay_pattern))
        print("Date       | Total | Details")
        print("-" * 40)
        for date, statuses in OrderedDict(sorted(daily_data.items(), key=lambda x: x[0])).items():
            month_number, day = date.split()
            month_name = [name for name, num in month_to_number.items() if num == month_number][0]
            formatted_date = "{} {}".format(month_name, int(day))  # 先頭の0を除去
            total = sum(statuses.values())
            details = ", ".join(["{}: {}".format(status, count) for status, count in statuses.items()])
            print("{:<10} | {:<5} | {}".format(formatted_date, total, details))
        print("")  # ホスト名ごとに区切りを入れる

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <path_to_log_file>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    analyze_log(log_file_path)
