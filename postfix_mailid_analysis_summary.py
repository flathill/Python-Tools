# -*- coding: utf-8 -*-
"""
Postfix maillog 解析スクリプト（拡張サマリ情報付加版、Python 2.7互換）

このスクリプトは、Postfixのmaillogから、メール送信試みとそれに関連するバウンスメールの情報を詳細に追跡し、
見やすく表示します。各Mail IDとBounce Mail IDについて、最初と最後のログの日時（年を除く）、および最終ステータスを表示します。

2024/2/1: by flathill <seiichirou.hiraoka@gmail.com>
実行方法: cat <maillog file> | python analyze-maillog.py
"""

# モジュールのインポート
import sys
import re
from collections import defaultdict
from datetime import datetime

def extract_mail_ids(log_lines):
    """
    ログからメールIDとそれに関連する情報を抽出し、関連付けます。

    :param log_lines: ログファイルの各行を要素とするリスト
    :return: メールIDをキー、関連する情報を値とする辞書
    """
    # メールIDとそれに関連する情報を格納する辞書
    # {
    #   'mail_id': {
    #     'related_ids': set(),
    #     'lines': [],
    #     'is_bounce': False,
    #     'dates': [],
    #     'final_status': None
    # }
    mail_info = defaultdict(lambda: {'related_ids': set(), 'lines': [], 'is_bounce': False, 'dates': [], 'final_status': None})
    # Mail ID抽出用正規表現    
    mail_id_pattern = re.compile(r'([0-9A-F]{10,12}):')
    # 日時抽出用正規表現    
    date_pattern = re.compile(r'^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})')
    # Bounce Mail ID抽出用正規表現
    bounce_notification_pattern = re.compile(r'([0-9A-F]{10,12}): sender non-delivery notification: ([0-9A-F]{10,12})')

    # ログの各行を処理します。
    for line in log_lines:
        # ログが日時にマッチするか判定します。        
        date_match = date_pattern.search(line)
        if date_match:
            date_str = date_match.group(1)
            # 年を含めない日時オブジェクトを生成
            date_obj = datetime.strptime(date_str, '%b %d %H:%M:%S').replace(year=1900)
        # ログが日時にマッチしない場合
        else:
            continue
        
        # ログがmail_idにマッチするか判定します。
        mail_id_match = mail_id_pattern.search(line)
        # ログがbounce_notificationにマッチするか判定します。
        bounce_notification_match = bounce_notification_pattern.search(line)
        
        # mail_idにマッチする場合
        if mail_id_match:
            mail_id = mail_id_match.group(1)
            mail_info[mail_id]['lines'].append(line)
            mail_info[mail_id]['dates'].append(date_obj)
            # bounce_notificationにマッチする場合
            if bounce_notification_match:
                original_mail_id = bounce_notification_match.group(1)
                bounce_mail_id = bounce_notification_match.group(2)
                mail_info[original_mail_id]['related_ids'].add(bounce_mail_id)
                mail_info[bounce_mail_id]['related_ids'].add(original_mail_id)
                mail_info[bounce_mail_id]['is_bounce'] = True

            # ステータスを取得
            for status in ['sent', 'bounced', 'deferred', 'expired']:
                if "status={}".format(status) in line:
                    mail_info[mail_id]['final_status'] = status.capitalize()

    # メールIDとそれに関連する情報を返します。
    return mail_info

def display_mail_info(mail_info):
    """
    抽出したメールIDとバウンスメールIDの情報を見やすく表示します。

    :param mail_info: メールIDをキー、関連する情報を値とする辞書
    """
    for mail_id, info in sorted(mail_info.items()):
        if info['dates']:
            first_date = min(info['dates']).strftime('%b %d %H:%M:%S')
            last_date = max(info['dates']).strftime('%b %d %H:%M:%S')
        else:
            first_date, last_date = 'N/A', 'N/A'
        final_status = info['final_status'] if info['final_status'] else 'Unknown'
        status_summary = "First Log: {}, Last Log: {}, Final Status: {}".format(first_date, last_date, final_status)

        # メール ID に関連する情報を表示するための処理
        print("\n=== Mail ID: {} ({}) ===".format(mail_id, status_summary))
        for line in info['lines']:
            print(line)

        # バウンスメール ID に関連する情報を表示するための処理
        for related_id in info['related_ids']:
            if related_id in mail_info and mail_info[related_id]['is_bounce']:
                related_info = mail_info[related_id]
                if related_info['dates']:
                    first_date_related = min(related_info['dates']).strftime('%b %d %H:%M:%S')
                    last_date_related = max(related_info['dates']).strftime('%b %d %H:%M:%S')
                else:
                    first_date_related, last_date_related = 'N/A', 'N/A'
                final_status_related = related_info['final_status'] if related_info['final_status'] else 'Unknown'
                status_summary_related = "First Log: {}, Last Log: {}, Final Status: {}".format(first_date_related, last_date_related, final_status_related)
                print("\n--- Related Bounce Mail ID: {} ({}) ---".format(related_id, status_summary_related))
                for bounce_line in related_info['lines']:
                    print(bounce_line)

# メイン関数
if __name__ == "__main__":
    # 標準入力からログ行を取得し、UTF-8 エンコーディングでデコードしたうえで、改行コードを除去したリストを作成します。 
    log_lines = [line.decode('utf-8').strip() for line in sys.stdin.readlines()]
    # メールIDとそれに関連する情報を抽出します。    
    mail_info = extract_mail_ids(log_lines)
    # mail_info をもとに、メールIDとそれに関連する情報を見やすく表示します。
    display_mail_info(mail_info)
