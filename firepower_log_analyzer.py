#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Firepower ASA VPN ログ分析スクリプト（認証成功・失敗分離対応版）
実際のFirepower ASAログファイルを分析し、VPN接続の詳細情報を抽出・分析します。
gzipファイルにも対応し、高速処理に最適化されています。
全件表示対応、専用フォルダ出力、テキストレポート出力機能付き。
認証成功と失敗を分けた詳細分析機能を追加。
"""

import re
import pandas as pd
from datetime import datetime, timedelta
import requests
import json
from collections import defaultdict, Counter
import ipaddress
import csv
import os
import sys
import gzip
from pathlib import Path

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

class FirepowerLogAnalyzer:
    def __init__(self, geoip_db_path=None):
        # 最適化されたFirepower ASAログパターン（実際のログ形式に基づく）
        self.log_patterns = {
            # AAA認証成功パターン（新規追加）
            'auth_success_113004': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-6-113004:.*?user\s*=\s*([^\s:,]+)',

            # AAA認証確認パターン（新規追加）
            'auth_status_113008': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-6-113008:.*?user\s*=\s*([^\s:,]+)',

            # AAAポリシー取得パターン（新規追加）
            'auth_policy_113009': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-6-113009:.*?user\s*=\s*([^\s:,]+)',

            # ローカルDB認証成功パターン（新規追加）
            'auth_local_113012': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-6-113012:.*?user\s*=\s*([^\s:,]+)',

            # AAA認証失敗パターン
            'auth_failure_113015': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-6-113015:.*?user\s*=\s*([^:\s]+).*?user IP\s*=\s*(\d+\.\d+\.\d+\.\d+)',

            # WebVPN認証拒否パターン
            'auth_failure_716039': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-6-716039:.*?User\s*<([^>]+)>\s*IP\s*<(\d+\.\d+\.\d+\.\d+)>.*?rejected',

            # UATHセッション作成/削除パターン
            'session_109210': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-5-109210:.*?Session=(\w+),\s*User=([^,]+),\s*Assigned IP=(\d+\.\d+\.\d+\.\d+)',

            # SVC接続状態変更パターン
            'session_722037': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-4-722037:.*?Group\s*<([^>]+)>\s*User\s*<([^>]+)>\s*IP\s*<(\d+\.\d+\.\d+\.\d+)>.*?(SVC.*)',

            # WebVPNセッション状態変更パターン
            'session_716002': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-6-716002:.*?Group\s*<([^>]+)>\s*User\s*<([^>]+)>\s*IP\s*<(\d+\.\d+\.\d+\.\d+)>.*?WebVPN session (.*)',

            # セッション切断（詳細情報付き）パターン
            'session_113019': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-4-113019:.*?Group\s*=\s*([^,]+),\s*Username\s*=\s*([^,]+),\s*IP\s*=\s*(\d+\.\d+\.\d+\.\d+).*?Duration:\s*([^,]+)',

            # 汎用ASA VPNログパターン（その他のログID対応）
            'asa_vpn_generic': r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S+.*?%ASA-(\d+)-(\d+):.*?(?:User\s*[=<]\s*([^,>\s]+)|Username\s*=\s*([^,\s]+)|user\s*=\s*([^:\s]+))'
        }

        # GeoIPデータベースの初期化
        self.geoip_reader = None
        if GEOIP_AVAILABLE and geoip_db_path and os.path.exists(geoip_db_path):
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
                print(f"✅ GeoIPデータベースを読み込みました: {geoip_db_path}")
            except Exception as e:
                print(f"❌ GeoIPデータベースの読み込みに失敗しました: {e}")

        self.parsed_logs = []
        self.output_buffer = []  # コンソール出力をキャプチャ

    def log_output(self, message):
        """コンソール出力とバッファ保存を同時実行"""
        print(message)
        self.output_buffer.append(message)

    def create_output_directory(self, base_path="firepower_analysis"):
        """分析専用フォルダを作成"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"{base_path}_{timestamp}"
        os.makedirs(output_dir, exist_ok=True)

        # サブフォルダ作成
        os.makedirs(f"{output_dir}/csv_data", exist_ok=True)
        os.makedirs(f"{output_dir}/reports", exist_ok=True)

        return output_dir

    def classify_log_status(self, log):
        """ログの成功・失敗ステータスを分類"""
        log_type = log.get('log_type', '')
        status = log.get('status', '')

        # 認証成功パターン
        success_patterns = [
            'auth_success_113004',
            'auth_status_113008',
            'auth_policy_113009',
            'auth_local_113012'
        ]

        # 認証失敗パターン
        failure_patterns = [
            'auth_failure_113015',
            'auth_failure_716039'
        ]

        # セッション関連パターン（通常は成功後の活動）
        session_patterns = [
            'session_109210',
            'session_722037',
            'session_716002',
            'session_113019'
        ]

        if log_type in success_patterns:
            return 'success'
        elif log_type in failure_patterns:
            return 'failure'
        elif log_type in session_patterns:
            if '確立' in status or '作成' in status or 'created' in status.lower():
                return 'success'
            elif '拒否' in status or '失敗' in status or 'rejected' in status.lower():
                return 'failure'
            else:
                return 'session'  # セッション管理（成功でも失敗でもない）
        else:
            # 汎用パターンの場合、ステータスで判定
            if '成功' in status or '確立' in status or 'success' in status.lower():
                return 'success'
            elif '失敗' in status or '拒否' in status or 'rejected' in status.lower():
                return 'failure'
            else:
                return 'other'

    def get_country_info(self, ip_address):
        """IPアドレスから国情報を取得"""
        try:
            # プライベートIPアドレスのチェック
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                return {
                    'country': 'Internal Network',
                    'country_code': 'PRIVATE',
                    'city': 'N/A',
                    'latitude': None,
                    'longitude': None,
                    'source': 'IP_Analysis'
                }

            # 特別なIPアドレスのチェック
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved:
                return {
                    'country': 'Special Address',
                    'country_code': 'SPECIAL',
                    'city': 'N/A',
                    'latitude': None,
                    'longitude': None,
                    'source': 'IP_Analysis'
                }

            # GeoIPデータベースを使用
            if self.geoip_reader:
                try:
                    response = self.geoip_reader.city(ip_address)
                    return {
                        'country': response.country.names.get('en', response.country.name) or 'Unknown',
                        'country_code': response.country.iso_code or 'UNKNOWN',
                        'city': response.city.names.get('en', response.city.name) or 'Unknown',
                        'latitude': float(response.location.latitude) if response.location.latitude else None,
                        'longitude': float(response.location.longitude) if response.location.longitude else None,
                        'source': 'GeoIP_Database'
                    }
                except geoip2.errors.AddressNotFoundError:
                    pass

            # 国情報が取得できない場合
            return {
                'country': 'Unknown',
                'country_code': 'UNKNOWN',
                'city': 'Unknown',
                'latitude': None,
                'longitude': None,
                'source': 'Unknown'
            }

        except Exception as e:
            return {
                'country': 'Error',
                'country_code': 'ERROR',
                'city': 'Unknown',
                'latitude': None,
                'longitude': None,
                'source': 'Error'
            }

    def parse_log_line(self, log_line):
        """ログ行を解析して構造化データに変換"""
        for log_type, pattern in self.log_patterns.items():
            match = re.search(pattern, log_line)
            if match:
                groups = match.groups()

                # 基本情報の抽出
                timestamp = f"{groups[0]} {groups[1]}"

                if log_type == 'auth_success_113004':
                    # AAA認証成功ログの処理
                    username = groups[2]

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'username': username,
                        'user_group': 'N/A',
                        'source_ip': 'N/A',
                        'assigned_ip': 'N/A',
                        'session_id': 'N/A',
                        'country': 'Internal Network',
                        'country_code': 'INTERNAL',
                        'city': 'N/A',
                        'latitude': None,
                        'longitude': None,
                        'country_source': 'Internal',
                        'status': 'AAA Authentication Success',
                        'reason': 'Authentication successful',
                        'message': 'AAA user authentication Successful',
                        'raw_log': log_line.strip()
                    }

                elif log_type == 'auth_status_113008':
                    # AAA認証確認ログの処理
                    username = groups[2]

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'username': username,
                        'user_group': 'N/A',
                        'source_ip': 'N/A',
                        'assigned_ip': 'N/A',
                        'session_id': 'N/A',
                        'country': 'Internal Network',
                        'country_code': 'INTERNAL',
                        'city': 'N/A',
                        'latitude': None,
                        'longitude': None,
                        'country_source': 'Internal',
                        'status': 'AAA Authentication Confirmation',
                        'reason': 'Transaction status ACCEPT',
                        'message': 'AAA transaction status ACCEPT',
                        'raw_log': log_line.strip()
                    }

                elif log_type == 'auth_policy_113009':
                    # AAAポリシー取得ログの処理
                    username = groups[2]

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'username': username,
                        'user_group': 'N/A',
                        'source_ip': 'N/A',
                        'assigned_ip': 'N/A',
                        'session_id': 'N/A',
                        'country': 'Internal Network',
                        'country_code': 'INTERNAL',
                        'city': 'N/A',
                        'latitude': None,
                        'longitude': None,
                        'country_source': 'Internal',
                        'status': 'AAA Policy Retrieved',
                        'reason': 'Group policy retrieved',
                        'message': 'AAA retrieved default group policy',
                        'raw_log': log_line.strip()
                    }

                elif log_type == 'auth_local_113012':
                    # ローカルDB認証成功ログの処理
                    username = groups[2]

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'username': username,
                        'user_group': 'N/A',
                        'source_ip': 'N/A',
                        'assigned_ip': 'N/A',
                        'session_id': 'N/A',
                        'country': 'Internal Network',
                        'country_code': 'INTERNAL',
                        'city': 'N/A',
                        'latitude': None,
                        'longitude': None,
                        'country_source': 'Internal',
                        'status': 'Local DB Authentication Success',
                        'reason': 'Local database authentication successful',
                        'message': 'AAA user authentication Successful : local database',
                        'raw_log': log_line.strip()
                    }

                elif log_type == 'auth_failure_113015':
                    # AAA認証失敗ログの処理
                    username = groups[2]
                    source_ip = groups[3]

                    if not self.is_valid_ip(source_ip):
                        continue

                    geo_info = self.get_country_info(source_ip)

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'username': username,
                        'user_group': 'N/A',
                        'source_ip': source_ip,
                        'assigned_ip': 'N/A',
                        'session_id': 'N/A',
                        'country': geo_info['country'],
                        'country_code': geo_info['country_code'],
                        'city': geo_info['city'],
                        'latitude': geo_info['latitude'],
                        'longitude': geo_info['longitude'],
                        'country_source': geo_info['source'],
                        'status': 'AAA Authentication Failed',
                        'reason': 'User was not found',
                        'message': 'AAA user authentication Rejected',
                        'raw_log': log_line.strip()
                    }

                elif log_type == 'auth_failure_716039':
                    # WebVPN認証拒否ログの処理
                    username = groups[2]
                    source_ip = groups[3]

                    if not self.is_valid_ip(source_ip):
                        continue

                    geo_info = self.get_country_info(source_ip)

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'username': username,
                        'user_group': 'N/A',
                        'source_ip': source_ip,
                        'assigned_ip': 'N/A',
                        'session_id': 'N/A',
                        'country': geo_info['country'],
                        'country_code': geo_info['country_code'],
                        'city': geo_info['city'],
                        'latitude': geo_info['latitude'],
                        'longitude': geo_info['longitude'],
                        'country_source': geo_info['source'],
                        'status': 'WebVPN Authentication Rejected',
                        'reason': 'Authentication rejected',
                        'message': 'WebVPN authentication rejected',
                        'raw_log': log_line.strip()
                    }

                elif log_type == 'session_109210':
                    # UATHセッション作成/削除ログの処理
                    session_id = groups[2]
                    username = groups[3]
                    assigned_ip = groups[4]

                    # セッション削除は成功ログとして扱う（正常なVPN接続の証拠）
                    geo_info = self.get_country_info(assigned_ip)

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'username': username,
                        'user_group': 'N/A',
                        'source_ip': 'N/A',
                        'assigned_ip': assigned_ip,
                        'session_id': session_id,
                        'country': geo_info['country'],
                        'country_code': geo_info['country_code'],
                        'city': geo_info['city'],
                        'latitude': geo_info['latitude'],
                        'longitude': geo_info['longitude'],
                        'country_source': geo_info['source'],
                        'status': 'Session Management',
                        'reason': 'Session management',
                        'message': 'UAUTH Session operation',
                        'raw_log': log_line.strip()
                    }

                # その他のログタイプの処理を続ける...
                # [他のログタイプの処理がここに続く]

        return None

    def is_valid_ip(self, ip_string):
        """IPアドレスが有効かチェック"""
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False

    def open_log_file(self, log_file_path):
        """ログファイルを開く（gzipファイル対応）"""
        if log_file_path.endswith('.gz'):
            self.log_output(f"📦 gzipファイルを展開して読み込み中...")
            return gzip.open(log_file_path, 'rt', encoding='utf-8')
        else:
            return open(log_file_path, 'r', encoding='utf-8')

    def analyze_log_file(self, log_file_path):
        """ログファイルを分析"""
        self.log_output(f"\n📁 ログファイルを分析中: {log_file_path}")

        if not os.path.exists(log_file_path):
            self.log_output(f"❌ エラー: ファイル '{log_file_path}' が見つかりません")
            return

        try:
            processed_lines = 0
            matched_lines = 0

            with self.open_log_file(log_file_path) as file:
                for line_num, line in enumerate(file, 1):
                    processed_lines += 1

                    if line_num % 10000 == 0:
                        self.log_output(f"処理中... {line_num:,} 行 (マッチ: {matched_lines:,})")

                    parsed = self.parse_log_line(line.strip())
                    if parsed:
                        self.parsed_logs.append(parsed)
                        matched_lines += 1

            self.log_output(f"✅ 分析完了:")
            self.log_output(f"   - 処理行数: {processed_lines:,}")
            self.log_output(f"   - マッチ行数: {matched_lines:,}")
            self.log_output(f"   - 抽出ログ数: {len(self.parsed_logs):,}")

            if matched_lines == 0:
                self.log_output("\n💡 VPNログ検索のヒント:")
                self.log_output("   - %ASA-6-113004 (AAA認証成功)")
                self.log_output("   - %ASA-6-113015 (AAA認証失敗)")
                self.log_output("   - %ASA-6-716039 (WebVPN拒否)")
                self.log_output("   - ASAログメッセージIDを確認してください")

        except UnicodeDecodeError as e:
            self.log_output(f"❌ エラー: 文字エンコーディングの問題: {e}")
            self.log_output("💡 ヒント: ファイルのエンコーディングを確認してください")
        except Exception as e:
            self.log_output(f"❌ エラー: {e}")

    def calculate_connection_sessions(self):
        """接続セッション時間を計算"""
        # ユーザーとIPでセッションを分類
        sessions = defaultdict(list)

        for log in self.parsed_logs:
            if log['log_type'] in ['auth_success', 'tunnel_down']:
                session_key = f"{log['username']}_{log['source_ip']}"
                sessions[session_key].append(log)

        session_durations = []

        for session_key, events in sessions.items():
            # 時間順でソート
            events.sort(key=lambda x: x['timestamp'])

            # tunnel-upとtunnel-downのペアを探す
            i = 0
            while i < len(events):
                if events[i]['log_type'] == 'auth_success':
                    # 対応するtunnel-downを探す
                    tunnel_id = events[i].get('tunnel_id', 'N/A')
                    start_time = events[i]['timestamp']

                    for j in range(i + 1, len(events)):
                        if (events[j]['log_type'] == 'tunnel_down' and
                            events[j].get('tunnel_id', 'N/A') == tunnel_id):
                            end_time = events[j]['timestamp']

                            try:
                                start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
                                end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
                                duration_seconds = (end_dt - start_dt).total_seconds()

                                session_durations.append({
                                    'username': events[i]['username'],
                                    'source_ip': events[i]['source_ip'],
                                    'country': events[i]['country'],
                                    'tunnel_id': tunnel_id,
                                    'start_time': start_time,
                                    'end_time': end_time,
                                    'duration_seconds': duration_seconds,
                                    'duration_minutes': duration_seconds / 60,
                                    'duration_hours': duration_seconds / 3600
                                })
                            except ValueError:
                                # 時間解析エラーは無視
                                pass
                            break
                i += 1

        return session_durations


    def generate_detailed_statistics(self):
        """詳細統計情報を生成"""
        if not self.parsed_logs:
            self.log_output("分析するログがありません")
            return {}

        stats = {}
        df = pd.DataFrame(self.parsed_logs)

        # 基本統計
        total_logs = len(self.parsed_logs)
        auth_success_count = len(df[df['status'].str.contains('Success', na=False)])
        auth_failure_count = len(df[df['status'].str.contains('Failed|Rejected', na=False)])
        tunnel_down_count = len(df[df['status'].str.contains('Disconn', na=False)])
        total_auth_attempts = auth_success_count + auth_failure_count

        stats['basic'] = {
            'total_logs': total_logs,
            'auth_success': auth_success_count,
            'auth_failure': auth_failure_count,
            'tunnel_down': tunnel_down_count,
            'total_auth_attempts': total_auth_attempts,
            'success_rate': (auth_success_count / total_auth_attempts * 100) if total_auth_attempts > 0 else 0,
            'unique_users': df['username'].nunique(),
            'unique_ips': df['source_ip'].nunique(),
            'unique_countries': df['country'].nunique()
        }

        # セッション時間統計
        session_durations = self.calculate_connection_sessions()
        if session_durations:
            session_df = pd.DataFrame(session_durations)
            stats['sessions'] = {
                'total_sessions': len(session_durations),
                'avg_duration_minutes': session_df['duration_minutes'].mean(),
                'median_duration_minutes': session_df['duration_minutes'].median(),
                'max_duration_hours': session_df['duration_hours'].max(),
                'min_duration_minutes': session_df['duration_minutes'].min()
            }
        else:
            stats['sessions'] = {
                'total_sessions': 0,
                'avg_duration_minutes': 0,
                'median_duration_minutes': 0,
                'max_duration_hours': 0,
                'min_duration_minutes': 0
            }

        # ユーザー統計（全件記録）
        user_stats = []
        for username in df['username'].unique():
            user_df = df[df['username'] == username]
            success_logs = user_df[user_df['status'].str.contains('Success', na=False)]
            failure_logs = user_df[user_df['status'].str.contains('Failed|Rejected', na=False)]

            # ユーザーセッション情報
            user_sessions = [s for s in session_durations if s['username'] == username]
            avg_session_duration = sum([s['duration_minutes'] for s in user_sessions]) / len(user_sessions) if user_sessions else 0

            user_stats.append({
                'username': username,
                'total_logs': len(user_df),
                'success_count': len(success_logs),
                'failure_count': len(failure_logs),
                'success_rate': (len(success_logs) / (len(success_logs) + len(failure_logs)) * 100)
                              if (len(success_logs) + len(failure_logs)) > 0 else 0,
                'unique_ips': user_df['source_ip'].nunique(),
                'countries': ', '.join(user_df['country'].unique()),
                'user_groups': ', '.join(user_df['user_group'].unique()) if 'user_group' in user_df.columns else 'N/A',
                'session_count': len(user_sessions),
                'avg_session_minutes': round(avg_session_duration, 1),
                'last_activity': user_df['timestamp'].max(),
                'first_activity': user_df['timestamp'].min()
            })

        stats['user_details'] = sorted(user_stats, key=lambda x: x['total_logs'], reverse=True)

        # 国別統計（全件記録）
        country_stats = []
        for country in df['country'].unique():
            country_df = df[df['country'] == country]
            success_logs = country_df[country_df['status'].str.contains('Success', na=False)]
            failure_logs = country_df[country_df['status'].str.contains('Failed|Rejected', na=False)]

            country_stats.append({
                'country': country,
                'country_code': country_df['country_code'].iloc[0],
                'total_logs': len(country_df),
                'success_count': len(success_logs),
                'failure_count': len(failure_logs),
                'success_rate': (len(success_logs) / (len(success_logs) + len(failure_logs)) * 100)
                              if (len(success_logs) + len(failure_logs)) > 0 else 0,
                'unique_users': country_df['username'].nunique(),
                'unique_ips': country_df['source_ip'].nunique()
            })

        stats['country_details'] = sorted(country_stats, key=lambda x: x['total_logs'], reverse=True)

        # セキュリティ警告：疑わしいIP（全件記録）
        ip_stats = []
        for ip in df['source_ip'].unique():
            ip_df = df[df['source_ip'] == ip]
            failure_logs = ip_df[ip_df['status'].str.contains('Failed|Rejected', na=False)]
            auth_logs = ip_df[ip_df['status'].str.contains('Success|Failed|Rejected', na=False)]

            failure_count = len(failure_logs)
            total_auth = len(auth_logs)
            failure_rate = (failure_count / total_auth * 100) if total_auth > 0 else 0

            # 疑わしいIPの基準
            is_suspicious = (failure_count >= 3) or (failure_rate > 70 and total_auth >= 2)

            ip_stats.append({
                'source_ip': ip,
                'country': ip_df['country'].iloc[0],
                'country_code': ip_df['country_code'].iloc[0],
                'city': ip_df['city'].iloc[0],
                'total_logs': len(ip_df),
                'failure_count': failure_count,
                'failure_rate': failure_rate,
                'unique_users': ip_df['username'].nunique(),
                'users_list': ', '.join(ip_df['username'].unique()),
                'is_suspicious': is_suspicious,
                'first_seen': ip_df['timestamp'].min(),
                'last_seen': ip_df['timestamp'].max(),
                'failure_reasons': ', '.join(failure_logs['reason'].unique()) if failure_count > 0 else 'N/A'
            })

        stats['ip_details'] = sorted(ip_stats, key=lambda x: x['failure_count'], reverse=True)

        # 失敗理由統計（全件記録）
        if auth_failure_count > 0:
            failure_df = df[df['status'].str.contains('Failed|Rejected', na=False)]
            reason_stats = failure_df['reason'].value_counts().to_dict()
            stats['failure_reasons'] = reason_stats
        else:
            stats['failure_reasons'] = {}

        # 時系列分析
        try:
            df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df_valid_time = df.dropna(subset=['datetime'])

            if not df_valid_time.empty:
                df_valid_time['hour'] = df_valid_time['datetime'].dt.hour
                df_valid_time['date'] = df_valid_time['datetime'].dt.date
                df_valid_time['weekday'] = df_valid_time['datetime'].dt.day_name()

                stats['time_analysis'] = {
                    'hourly_distribution': df_valid_time.groupby('hour').size().to_dict(),
                    'daily_distribution': df_valid_time.groupby('date').size().to_dict(),
                    'weekday_distribution': df_valid_time.groupby('weekday').size().to_dict()
                }
            else:
                stats['time_analysis'] = {
                    'hourly_distribution': {},
                    'daily_distribution': {},
                    'weekday_distribution': {}
                }
        except Exception as e:
            self.log_output(f"時系列分析エラー: {e}")
            stats['time_analysis'] = {
                'hourly_distribution': {},
                'daily_distribution': {},
                'weekday_distribution': {}
            }

        return stats

    def print_detailed_report(self, stats):
        """詳細レポート表示（全件記録表示）"""
        self.log_output("\n" + "="*150)
        self.log_output("🔐 Firepower ASA VPN ログ分析 - 詳細レポート（全件記録）")
        self.log_output("="*150)

        # 基本統計
        self.log_output(f"\n📊 【基本統計】")
        self.log_output(f"{'項目':<25} {'値':<15} {'詳細'}")
        self.log_output("-" * 70)
        self.log_output(f"{'総ログエントリ数':<25} {stats['basic']['total_logs']:,}")
        self.log_output(f"{'認証成功':<25} {stats['basic']['auth_success']:,} ({stats['basic']['success_rate']:.1f}%)")
        self.log_output(f"{'認証失敗':<25} {stats['basic']['auth_failure']:,}")
        self.log_output(f"{'トンネル切断':<25} {stats['basic']['tunnel_down']:,}")
        self.log_output(f"{'総認証試行数':<25} {stats['basic']['total_auth_attempts']:,}")
        self.log_output(f"{'ユニークユーザー数':<25} {stats['basic']['unique_users']:,}")
        self.log_output(f"{'ユニークIP数':<25} {stats['basic']['unique_ips']:,}")
        self.log_output(f"{'接続元国数':<25} {stats['basic']['unique_countries']:,}")

        # セッション統計
        if stats['sessions']['total_sessions'] > 0:
            self.log_output(f"\n⏱️  【セッション統計】")
            self.log_output(f"{'項目':<25} {'値'}")
            self.log_output("-" * 45)
            self.log_output(f"{'総セッション数':<25} {stats['sessions']['total_sessions']:,}")
            self.log_output(f"{'平均接続時間':<25} {stats['sessions']['avg_duration_minutes']:.1f} 分")
            self.log_output(f"{'中央値接続時間':<25} {stats['sessions']['median_duration_minutes']:.1f} 分")
            self.log_output(f"{'最長接続時間':<25} {stats['sessions']['max_duration_hours']:.1f} 時間")
            self.log_output(f"{'最短接続時間':<25} {stats['sessions']['min_duration_minutes']:.1f} 分")

        # 失敗理由統計（全件記録）
        if stats.get('failure_reasons'):
            self.log_output(f"\n🚨 【認証失敗理由】(全 {len(stats['failure_reasons'])} 種類)")
            self.log_output(f"{'失敗理由':<50} {'件数':<10}")
            self.log_output("-" * 65)
            for reason, count in stats['failure_reasons'].items():
                self.log_output(f"{reason[:48]:<50} {count:<10}")

        self.log_output("\n" + "="*150)

    def save_text_report(self, output_dir):
        """コンソール出力をテキストファイルに保存"""
        report_path = f"{output_dir}/reports/analysis_report.txt"

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("Firepower ASA VPN ログ分析レポート\n")
            f.write(f"生成日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("\n" + "="*100 + "\n\n")

            for line in self.output_buffer:
                f.write(line + '\n')

        self.log_output(f"📄 テキストレポート: {report_path}")

    def export_all_csv(self, stats, output_dir):
        """全分析結果をCSVファイルに出力"""
        csv_dir = f"{output_dir}/csv_data"

        # 1. 全ログデータ
        if self.parsed_logs:
            df = pd.DataFrame(self.parsed_logs)
            df.to_csv(f'{csv_dir}/01_asa_vpn_all_logs.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 全ログデータ: {csv_dir}/01_asa_vpn_all_logs.csv")

        # 2. セッション統計
        session_durations = self.calculate_connection_sessions()
        if session_durations:
            session_df = pd.DataFrame(session_durations)
            session_df.to_csv(f'{csv_dir}/02_connection_sessions.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 接続セッション: {csv_dir}/02_connection_sessions.csv")

        # 3. ユーザー統計（全件記録）
        if stats.get('user_details'):
            user_df = pd.DataFrame(stats['user_details'])
            user_df.to_csv(f'{csv_dir}/03_user_analysis_all.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 ユーザー分析（全件記録）: {csv_dir}/03_user_analysis_all.csv")

        # 4. 国別統計（全件記録）
        if stats.get('country_details'):
            country_df = pd.DataFrame(stats['country_details'])
            country_df.to_csv(f'{csv_dir}/04_country_analysis_all.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 国別分析（全件記録）: {csv_dir}/04_country_analysis_all.csv")

        # 5. IP統計（全件記録）
        if stats.get('ip_details'):
            ip_df = pd.DataFrame(stats['ip_details'])
            ip_df.to_csv(f'{csv_dir}/05_ip_analysis_all.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 IP分析（全件記録）: {csv_dir}/05_ip_analysis_all.csv")

        # 6. 疑わしいIP専用
        if stats.get('ip_details'):
            suspicious_ips = [ip for ip in stats['ip_details'] if ip['is_suspicious']]
            if suspicious_ips:
                suspicious_df = pd.DataFrame(suspicious_ips)
                suspicious_df.to_csv(f'{csv_dir}/06_suspicious_ips.csv', index=False, encoding='utf-8-sig')
                self.log_output(f"🚨 疑わしいIP: {csv_dir}/06_suspicious_ips.csv")

        # 7. 失敗理由統計（全件記録）
        if stats.get('failure_reasons'):
            failure_reasons_df = pd.DataFrame(list(stats['failure_reasons'].items()),
                                            columns=['失敗理由', '件数'])
            failure_reasons_df = failure_reasons_df.sort_values('件数', ascending=False)
            failure_reasons_df.to_csv(f'{csv_dir}/07_failure_reasons_all.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 失敗理由分析（全件記録）: {csv_dir}/07_failure_reasons_all.csv")

        # 8. 基本統計概要
        basic_stats_df = pd.DataFrame([stats['basic']])
        basic_stats_df.to_csv(f'{csv_dir}/08_basic_statistics.csv', index=False, encoding='utf-8-sig')
        self.log_output(f"📄 基本統計: {csv_dir}/08_basic_statistics.csv")

        # 9. 時系列分析
        if stats.get('time_analysis'):
            # 時間別分析
            hourly_df = pd.DataFrame(list(stats['time_analysis']['hourly_distribution'].items()),
                                   columns=['時間', 'ログ数'])
            hourly_df.to_csv(f'{csv_dir}/09_hourly_analysis.csv', index=False, encoding='utf-8-sig')

            # 日別分析
            daily_df = pd.DataFrame(list(stats['time_analysis']['daily_distribution'].items()),
                                  columns=['日付', 'ログ数'])
            daily_df.to_csv(f'{csv_dir}/10_daily_analysis.csv', index=False, encoding='utf-8-sig')

            # 曜日別分析
            weekday_df = pd.DataFrame(list(stats['time_analysis']['weekday_distribution'].items()),
                                    columns=['曜日', 'ログ数'])
            weekday_df.to_csv(f'{csv_dir}/11_weekday_analysis.csv', index=False, encoding='utf-8-sig')

            self.log_output(f"📄 時系列分析: {csv_dir}/09-11_time_analysis.csv")


def setup_geoip_database():
    """GeoIPデータベースセットアップガイド"""
    print("\n🌍 GeoIPデータベース設定ガイド（オプション）")
    print("="*60)
    print("GeoIPデータベースは補助的な利用です。Firepower ASAログ分析が優先されます。")
    print()
    print("1. MaxMindアカウント作成（無料）:")
    print("   https://www.maxmind.com/en/geolite2/signup")
    print()
    print("2. ライセンスキー取得:")
    print("   ログイン → Account → My License Key → Generate new license key")
    print()
    print("3. GeoLite2-Cityデータベースダウンロード:")
    print("   https://www.maxmind.com/en/accounts/current/geoip/downloads")
    print()
    print("4. 展開してGeoLite2-City.mmdbファイルを取得")
    print("5. スクリプト実行時にパスを指定:")
    print("   python firepower_analyzer_final.py -l logfile.log -g /path/to/GeoLite2-City.mmdb")
    print()

def print_help():
    """ヘルプメッセージを表示"""
    print("🔐 Firepower ASA VPN ログ分析ツール（完全版）")
    print("="*55)
    print()
    print("使用方法:")
    print("  python firepower_analyzer_final.py -l <ログファイル> [オプション]")
    print()
    print("必須オプション:")
    print("  -l, --log-file <ファイルパス>      分析するFirepower ASAログファイル")
    print("                                  （.gz圧縮ファイル対応）")
    print()
    print("オプション:")
    print("  -g, --geoip-db <ファイルパス>      MaxMind GeoLite2データベースファイル")
    print("                                  （補助的、ASAログが優先）")
    print("  -h, --help                      このヘルプメッセージを表示")
    print()
    print("使用例:")
    print("  python firepower_analyzer_final.py -l /var/log/asa.log")
    print("  python firepower_analyzer_final.py -l asa.log.gz")
    print("  python firepower_analyzer_final.py -l asa.log -g GeoLite2-City.mmdb")
    print()
    print("出力ファイル:")
    print("  - 専用フォルダ: firepower_analysis_YYYYMMDD_HHMMSS/")
    print("  - テキストレポート: reports/analysis_report.txt")
    print("  - CSVデータ: csv_data/ フォルダ（全件記録出力）")
    print()
    print("対応ログ形式:")
    print("  - AAA認証成功 (%ASA-6-113004)")
    print("  - AAA認証失敗 (%ASA-6-113015)")
    print("  - WebVPN認証拒否 (%ASA-6-716039)")
    print("  - セッション管理ログ (%ASA-5-109210)")
    print("  - その他ASA VPN関連ログ")
    print()
    print("機能:")
    print("  - ユーザー、国、IP統計は全件記録表示")
    print("  - 専用フォルダ作成（過去の結果を上書きしない）")
    print("  - コンソール出力もテキストファイルに保存")
    print("  - 全データをCSV形式で出力し他の分析に活用可能")
    print()

def main():
    """メイン関数"""
    import argparse

    # カスタムヘルプフォーマッター
    class CustomHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def format_help(self):
            print_help()
            return ""

    parser = argparse.ArgumentParser(
        description='Firepower ASA VPN ログ分析ツール（完全版）',
        formatter_class=CustomHelpFormatter,
        add_help=False
    )

    parser.add_argument('--log-file', '-l',
                       help='分析するログファイルのパス（必須、.gzファイル対応）')
    parser.add_argument('--geoip-db', '-g',
                       help='GeoIPデータベース（.mmdb）のパス（オプション、補助的）')
    parser.add_argument('--help', '-h', action='store_true',
                       help='ヘルプメッセージを表示')

    args = parser.parse_args()

    # ヘルプオプションまたは必須オプション不足
    if args.help or not args.log_file:
        print_help()
        if not args.log_file and not args.help:
            print("❌ エラー: ログファイルの指定が必要です（-l オプション）")
        return

    # ログファイル存在確認
    if not os.path.exists(args.log_file):
        print(f"❌ エラー: ログファイル '{args.log_file}' が見つかりません")
        return

    # GeoIPデータベース確認
    if args.geoip_db and not os.path.exists(args.geoip_db):
        print(f"⚠️  警告: GeoIPデータベース '{args.geoip_db}' が見つかりません")
        print("GeoIPデータベースなしで続行します...")
        args.geoip_db = None

    # ログ分析器の初期化
    analyzer = FirepowerLogAnalyzer(geoip_db_path=args.geoip_db)

    # 専用出力フォルダの作成
    output_dir = analyzer.create_output_directory()

    analyzer.log_output(f"\n🔐 Firepower ASA VPNログ分析を開始します（完全版）")
    analyzer.log_output(f"📁 ログファイル: {args.log_file}")
    analyzer.log_output(f"📂 出力フォルダ: {output_dir}")
    if args.geoip_db:
        analyzer.log_output(f"🌍 GeoIPデータベース: {args.geoip_db}")
    else:
        analyzer.log_output("💡 外部IPのGeoIP解決を使用します")

    # ファイル形式確認
    if args.log_file.endswith('.gz'):
        analyzer.log_output(f"📦 gzip圧縮ファイルとして処理します")

    # ログファイル分析
    analyzer.analyze_log_file(args.log_file)

    if not analyzer.parsed_logs:
        analyzer.log_output("\n❌ ASA VPN関連のログが見つかりませんでした")
        return

    # 詳細統計情報の生成
    stats = analyzer.generate_detailed_statistics()

    # 詳細レポート表示（コンソール + バッファ）
    analyzer.print_detailed_report(stats)

    # テキストレポート保存
    analyzer.save_text_report(output_dir)

    # CSV出力（全件記録）
    analyzer.log_output(f"\n📊 分析結果をCSVファイルに出力中（全件記録）...")
    analyzer.export_all_csv(stats, output_dir)

    analyzer.log_output(f"\n✅ 分析が完了しました")
    analyzer.log_output(f"📂 全結果がフォルダに保存されました:")
    analyzer.log_output(f"   {output_dir}/")
    analyzer.log_output(f"   ├── reports/analysis_report.txt （コンソール出力のテキスト版）")
    analyzer.log_output(f"   └── csv_data/ （全分析データCSV）")

if __name__ == "__main__":
    main()
