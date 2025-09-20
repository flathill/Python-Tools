#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fortigate SSL-VPN ログ分析スクリプト
実際のFortigateログファイルを分析し、SSL-VPN接続の詳細情報を抽出・分析します。
gzipファイルにも対応し、Fortigateログの srccountry フィールドを優先使用します。
全件表示対応、専用フォルダ出力、テキストレポート出力機能付き。
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

class SSLVPNLogAnalyzer:
    def __init__(self, geoip_db_path=None):
        # 実際のFortigateログパターン（提供されたログ形式に基づく）
        self.log_patterns = {
            # SSL-VPN認証失敗パターン
            'auth_failure': r'date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2}).*?logid="0101039426".*?subtype="vpn".*?level="alert".*?logdesc="SSL VPN login fail".*?action="ssl-login-fail".*?remip=(\d+\.\d+\.\d+\.\d+).*?srccountry="([^"]*)".*?user="([^"]*)".*?group="([^"]*)".*?reason="([^"]*)".*?msg="([^"]*)"',

            # SSL-VPN認証成功パターン（実際のログに基づく）
            'auth_success': r'date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2}).*?logid="0101039947".*?subtype="vpn".*?level="information".*?logdesc="SSL VPN tunnel up".*?action="tunnel-up".*?tunneltype="([^"]*)".*?tunnelid=(\d+).*?remip=(\d+\.\d+\.\d+\.\d+).*?tunnelip=(\d+\.\d+\.\d+\.\d+).*?srccountry="([^"]*)".*?user="([^"]*)".*?group="([^"]*)".*?reason="([^"]*)".*?msg="([^"]*)"',

            # SSL-VPN トンネル切断（想定）
            'tunnel_down': r'date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2}).*?logid="0101039948".*?subtype="vpn".*?level="information".*?logdesc="SSL VPN tunnel down".*?action="tunnel-down".*?tunneltype="([^"]*)".*?tunnelid=(\d+).*?remip=(\d+\.\d+\.\d+\.\d+).*?tunnelip=(\d+\.\d+\.\d+\.\d+).*?srccountry="([^"]*)".*?user="([^"]*)".*?group="([^"]*)".*?reason="([^"]*)".*?msg="([^"]*)"',

            # 汎用SSL-VPNログパターン（その他のログID対応）
            'ssl_vpn_generic': r'date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2}).*?logid="(\d+)".*?subtype="vpn".*?level="([^"]*)".*?action="([^"]*)".*?remip=(\d+\.\d+\.\d+\.\d+)(?:.*?srccountry="([^"]*)")?.*?user="([^"]*)"(?:.*?group="([^"]*)")?(?:.*?reason="([^"]*)")?.*?msg="([^"]*)"'
        }

        # GeoIPデータベースの初期化（補完用）
        self.geoip_reader = None
        if GEOIP_AVAILABLE and geoip_db_path and os.path.exists(geoip_db_path):
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
                print(f"✅ GeoIPデータベースを読み込みました（補完用）: {geoip_db_path}")
            except Exception as e:
                print(f"❌ GeoIPデータベースの読み込みに失敗: {e}")

        self.parsed_logs = []
        self.output_buffer = []  # コンソール出力をキャプチャ

    def log_output(self, message):
        """コンソール出力とバッファ保存を同時に行う"""
        print(message)
        self.output_buffer.append(message)

    def create_output_directory(self, base_path="fortigate_analysis"):
        """分析用の専用フォルダを作成"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"{base_path}_{timestamp}"
        os.makedirs(output_dir, exist_ok=True)

        # サブフォルダも作成
        os.makedirs(f"{output_dir}/csv_data", exist_ok=True)
        os.makedirs(f"{output_dir}/reports", exist_ok=True)

        return output_dir

    def get_country_info(self, ip_address, log_country=None):
        """IPアドレスと国名情報を統合して処理"""
        try:
            # プライベートIPアドレスのチェック
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                return {
                    'country': '社内ネットワーク',
                    'country_code': 'PRIVATE',
                    'city': 'N/A',
                    'latitude': None,
                    'longitude': None,
                    'source': 'IP_Analysis'
                }

            # 特殊なIPアドレスをチェック
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved:
                return {
                    'country': '特殊アドレス',
                    'country_code': 'SPECIAL',
                    'city': 'N/A',
                    'latitude': None,
                    'longitude': None,
                    'source': 'IP_Analysis'
                }

            # 1. Fortigateログの srccountry を優先使用
            if log_country and log_country != 'N/A' and log_country.strip():
                country_code = self.get_country_code_from_name(log_country)

                # GeoIPで都市情報を補完（利用可能な場合）
                city = 'N/A'
                latitude = None
                longitude = None

                if self.geoip_reader:
                    try:
                        response = self.geoip_reader.city(ip_address)
                        city = response.city.names.get('ja', response.city.name) or 'N/A'
                        latitude = float(response.location.latitude) if response.location.latitude else None
                        longitude = float(response.location.longitude) if response.location.longitude else None
                    except geoip2.errors.AddressNotFoundError:
                        pass

                return {
                    'country': log_country,
                    'country_code': country_code,
                    'city': city,
                    'latitude': latitude,
                    'longitude': longitude,
                    'source': 'Fortigate_Log'
                }

            # 2. GeoIPデータベースを使用（Fortigateログに国情報がない場合）
            if self.geoip_reader:
                try:
                    response = self.geoip_reader.city(ip_address)
                    return {
                        'country': response.country.names.get('ja', response.country.name) or '不明',
                        'country_code': response.country.iso_code or 'UNKNOWN',
                        'city': response.city.names.get('ja', response.city.name) or '不明',
                        'latitude': float(response.location.latitude) if response.location.latitude else None,
                        'longitude': float(response.location.longitude) if response.location.longitude else None,
                        'source': 'GeoIP_Database'
                    }
                except geoip2.errors.AddressNotFoundError:
                    pass

            # 3. 国情報が取得できない場合
            return {
                'country': '不明',
                'country_code': 'UNKNOWN',
                'city': '不明',
                'latitude': None,
                'longitude': None,
                'source': 'Unknown'
            }

        except Exception as e:
            return {
                'country': 'エラー',
                'country_code': 'ERROR',
                'city': '不明',
                'latitude': None,
                'longitude': None,
                'source': 'Error'
            }

    def get_country_code_from_name(self, country_name):
        """国名からISO国別コードを取得（簡易マッピング）"""
        country_mapping = {
            # 主要国のマッピング
            'United States': 'US', 'Germany': 'DE', 'Japan': 'JP', 'China': 'CN',
            'United Kingdom': 'GB', 'France': 'FR', 'Canada': 'CA', 'Australia': 'AU',
            'Brazil': 'BR', 'India': 'IN', 'Russia': 'RU', 'South Korea': 'KR',
            'Netherlands': 'NL', 'Switzerland': 'CH', 'Sweden': 'SE', 'Norway': 'NO',
            'Denmark': 'DK', 'Finland': 'FI', 'Belgium': 'BE', 'Austria': 'AT',
            'Spain': 'ES', 'Italy': 'IT', 'Portugal': 'PT', 'Poland': 'PL',
            'Czech Republic': 'CZ', 'Hungary': 'HU', 'Romania': 'RO', 'Bulgaria': 'BG',
            'Greece': 'GR', 'Turkey': 'TR', 'Israel': 'IL', 'Saudi Arabia': 'SA',
            'United Arab Emirates': 'AE', 'Singapore': 'SG', 'Thailand': 'TH',
            'Malaysia': 'MY', 'Indonesia': 'ID', 'Philippines': 'PH', 'Vietnam': 'VN',
            'Taiwan': 'TW', 'Hong Kong': 'HK', 'Mexico': 'MX', 'Argentina': 'AR',
            'Chile': 'CL', 'South Africa': 'ZA', 'Egypt': 'EG', 'Nigeria': 'NG',
            'Kenya': 'KE', 'Ukraine': 'UA', 'Belarus': 'BY', 'Lithuania': 'LT',
            'Latvia': 'LV', 'Estonia': 'EE', 'Ireland': 'IE', 'Iceland': 'IS',
            'Luxembourg': 'LU', 'Slovenia': 'SI', 'Croatia': 'HR', 'Serbia': 'RS',
            'Bosnia and Herzegovina': 'BA', 'Montenegro': 'ME', 'Albania': 'AL',
            'Macedonia': 'MK', 'Moldova': 'MD', 'Georgia': 'GE', 'Armenia': 'AM',
            'Azerbaijan': 'AZ', 'Kazakhstan': 'KZ', 'Uzbekistan': 'UZ',
            'Kyrgyzstan': 'KG', 'Tajikistan': 'TJ', 'Turkmenistan': 'TM',
            'Mongolia': 'MN', 'Nepal': 'NP', 'Bangladesh': 'BD', 'Sri Lanka': 'LK',
            'Myanmar': 'MM', 'Cambodia': 'KH', 'Laos': 'LA', 'New Zealand': 'NZ',
            'Papua New Guinea': 'PG', 'Fiji': 'FJ'
        }

        return country_mapping.get(country_name, 'UNKNOWN')

    def parse_log_line(self, log_line):
        """ログ行を解析して構造化データに変換"""
        for log_type, pattern in self.log_patterns.items():
            match = re.search(pattern, log_line)
            if match:
                groups = match.groups()

                # 基本情報の抽出
                timestamp = f"{groups[0]} {groups[1]}"

                if log_type == 'auth_failure':
                    # 認証失敗ログの処理
                    source_ip = groups[2]
                    log_country = groups[3] if groups[3] else None
                    username = groups[4]
                    user_group = groups[5]
                    reason = groups[6]
                    msg = groups[7]

                    # IPアドレスが有効かチェック
                    if not self.is_valid_ip(source_ip):
                        continue

                    # 国情報を取得（Fortigateログを優先）
                    geo_info = self.get_country_info(source_ip, log_country)

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'username': username,
                        'user_group': user_group,
                        'source_ip': source_ip,
                        'tunnel_ip': 'N/A',
                        'tunnel_id': 'N/A',
                        'tunnel_type': 'N/A',
                        'country': geo_info['country'],
                        'country_code': geo_info['country_code'],
                        'city': geo_info['city'],
                        'latitude': geo_info['latitude'],
                        'longitude': geo_info['longitude'],
                        'country_source': geo_info['source'],
                        'status': '認証失敗',
                        'reason': reason,
                        'message': msg,
                        'raw_log': log_line.strip()
                    }

                elif log_type == 'auth_success':
                    # 認証成功ログの処理（実際のログに基づく）
                    tunnel_type = groups[2]
                    tunnel_id = groups[3]
                    source_ip = groups[4]
                    tunnel_ip = groups[5]
                    log_country = groups[6] if groups[6] else None
                    username = groups[7]
                    user_group = groups[8]
                    reason = groups[9]
                    msg = groups[10]

                    if not self.is_valid_ip(source_ip):
                        continue

                    # 国情報を取得
                    geo_info = self.get_country_info(source_ip, log_country)

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'username': username,
                        'user_group': user_group,
                        'source_ip': source_ip,
                        'tunnel_ip': tunnel_ip,
                        'tunnel_id': tunnel_id,
                        'tunnel_type': tunnel_type,
                        'country': geo_info['country'],
                        'country_code': geo_info['country_code'],
                        'city': geo_info['city'],
                        'latitude': geo_info['latitude'],
                        'longitude': geo_info['longitude'],
                        'country_source': geo_info['source'],
                        'status': '認証成功',
                        'reason': reason,
                        'message': msg,
                        'raw_log': log_line.strip()
                    }

                elif log_type == 'tunnel_down':
                    # トンネル切断ログの処理（想定パターン）
                    tunnel_type = groups[2]
                    tunnel_id = groups[3]
                    source_ip = groups[4]
                    tunnel_ip = groups[5]
                    log_country = groups[6] if groups[6] else None
                    username = groups[7]
                    user_group = groups[8]
                    reason = groups[9]
                    msg = groups[10]

                    if not self.is_valid_ip(source_ip):
                        continue

                    # 国情報を取得
                    geo_info = self.get_country_info(source_ip, log_country)

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'username': username,
                        'user_group': user_group,
                        'source_ip': source_ip,
                        'tunnel_ip': tunnel_ip,
                        'tunnel_id': tunnel_id,
                        'tunnel_type': tunnel_type,
                        'country': geo_info['country'],
                        'country_code': geo_info['country_code'],
                        'city': geo_info['city'],
                        'latitude': geo_info['latitude'],
                        'longitude': geo_info['longitude'],
                        'country_source': geo_info['source'],
                        'status': 'トンネル切断',
                        'reason': reason,
                        'message': msg,
                        'raw_log': log_line.strip()
                    }

                elif log_type == 'ssl_vpn_generic':
                    # 汎用SSL-VPNログの処理
                    logid = groups[2]
                    level = groups[3]
                    action = groups[4]
                    source_ip = groups[5]
                    log_country = groups[6] if len(groups) > 6 and groups[6] else None
                    username = groups[7] if len(groups) > 7 else 'N/A'
                    user_group = groups[8] if len(groups) > 8 and groups[8] else 'N/A'
                    reason = groups[9] if len(groups) > 9 and groups[9] else 'N/A'
                    msg = groups[10] if len(groups) > 10 else 'N/A'

                    if not self.is_valid_ip(source_ip):
                        continue

                    # 国情報を取得
                    geo_info = self.get_country_info(source_ip, log_country)

                    # アクションから状態を判定
                    if 'fail' in action.lower() or level == 'alert':
                        status = '認証失敗'
                    elif 'tunnel-up' in action.lower():
                        status = '認証成功'
                    elif 'tunnel-down' in action.lower():
                        status = 'トンネル切断'
                    elif 'success' in action.lower() or 'login' in action.lower():
                        status = '認証成功'
                    elif 'logout' in action.lower():
                        status = 'ログアウト'
                    else:
                        status = f'その他 ({action})'

                    return {
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'logid': logid,
                        'username': username,
                        'user_group': user_group,
                        'source_ip': source_ip,
                        'tunnel_ip': 'N/A',
                        'tunnel_id': 'N/A',
                        'tunnel_type': 'N/A',
                        'country': geo_info['country'],
                        'country_code': geo_info['country_code'],
                        'city': geo_info['city'],
                        'latitude': geo_info['latitude'],
                        'longitude': geo_info['longitude'],
                        'country_source': geo_info['source'],
                        'status': status,
                        'reason': reason,
                        'message': msg,
                        'action': action,
                        'level': level,
                        'raw_log': log_line.strip()
                    }

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
            self.log_output(f"   - 処理した行数: {processed_lines:,}")
            self.log_output(f"   - マッチした行数: {matched_lines:,}")
            self.log_output(f"   - 抽出されたログ: {len(self.parsed_logs):,}")

            if matched_lines == 0:
                self.log_output("\n💡 SSL-VPN関連ログの検索ヒント:")
                self.log_output("   - logid=\"0101039426\" (SSL VPN login fail)")
                self.log_output("   - logid=\"0101039947\" (SSL VPN tunnel up)")
                self.log_output("   - logid=\"0101039948\" (SSL VPN tunnel down)")
                self.log_output("   - subtype=\"vpn\"")
                self.log_output("   - action=\"ssl-login-fail\" または action=\"tunnel-up\"")

                # サンプルログの最初の数行を表示（デバッグ用）
                self.log_output("\n🔍 ログファイルの最初の数行をサンプル表示:")
                try:
                    with self.open_log_file(log_file_path) as file:
                        for i, line in enumerate(file):
                            if i >= 5:  # 最初の5行のみ表示
                                break
                            self.log_output(f"   {i+1}: {line.strip()[:120]}{'...' if len(line.strip()) > 120 else ''}")
                except Exception as e:
                    self.log_output(f"   サンプル表示エラー: {e}")
            else:
                # 国情報のソース統計を表示
                country_sources = Counter([log.get('country_source', 'Unknown') for log in self.parsed_logs])
                self.log_output(f"\n📍 国情報の取得元:")
                for source, count in country_sources.items():
                    source_desc = {
                        'Fortigate_Log': 'Fortigateログ内の srccountry フィールド',
                        'GeoIP_Database': 'GeoIPデータベース',
                        'IP_Analysis': 'IPアドレス分析',
                        'Unknown': '不明'
                    }.get(source, source)
                    self.log_output(f"   - {source_desc}: {count:,} 件")

                # ログタイプ別統計を表示
                log_types = Counter([log.get('log_type', 'Unknown') for log in self.parsed_logs])
                self.log_output(f"\n📋 ログタイプ別統計:")
                for log_type, count in log_types.items():
                    type_desc = {
                        'auth_failure': 'SSL-VPN認証失敗',
                        'auth_success': 'SSL-VPN認証成功（トンネル確立）',
                        'tunnel_down': 'SSL-VPNトンネル切断',
                        'ssl_vpn_generic': 'その他SSL-VPNログ'
                    }.get(log_type, log_type)
                    self.log_output(f"   - {type_desc}: {count:,} 件")

        except UnicodeDecodeError as e:
            self.log_output(f"❌ エラー: 文字エンコーディングの問題です: {e}")
            self.log_output("💡 ヒント: ファイルのエンコーディングを確認してください")
        except Exception as e:
            self.log_output(f"❌ エラー: {e}")

    def calculate_connection_sessions(self):
        """接続セッションの継続時間を計算"""
        # ユーザー・IP別にセッションを分類
        sessions = defaultdict(list)

        for log in self.parsed_logs:
            if log['log_type'] in ['auth_success', 'tunnel_down']:
                session_key = f"{log['username']}_{log['source_ip']}"
                sessions[session_key].append(log)

        session_durations = []

        for session_key, events in sessions.items():
            # 時間順にソート
            events.sort(key=lambda x: x['timestamp'])

            # tunnel-up と tunnel-down のペアを探す
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
        auth_success_count = len(df[df['status'].str.contains('成功', na=False)])
        auth_failure_count = len(df[df['status'].str.contains('失敗', na=False)])
        tunnel_down_count = len(df[df['status'].str.contains('切断', na=False)])
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

        # セッション継続時間統計
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

        # ユーザー別統計（全件）
        user_stats = []
        for username in df['username'].unique():
            user_df = df[df['username'] == username]
            success_logs = user_df[user_df['status'].str.contains('成功', na=False)]
            failure_logs = user_df[user_df['status'].str.contains('失敗', na=False)]

            # ユーザーのセッション情報
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

        # 国別統計（全件）
        country_stats = []
        for country in df['country'].unique():
            country_df = df[df['country'] == country]
            success_logs = country_df[country_df['status'].str.contains('成功', na=False)]
            failure_logs = country_df[country_df['status'].str.contains('失敗', na=False)]

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

        # セキュリティ警告：疑わしいIP（全件）
        ip_stats = []
        for ip in df['source_ip'].unique():
            ip_df = df[df['source_ip'] == ip]
            failure_logs = ip_df[ip_df['status'].str.contains('失敗', na=False)]
            auth_logs = ip_df[ip_df['status'].str.contains('成功|失敗', na=False)]

            failure_count = len(failure_logs)
            total_auth = len(auth_logs)
            failure_rate = (failure_count / total_auth * 100) if total_auth > 0 else 0

            # 疑わしいIPの判定基準
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

        # 失敗理由統計（全件）
        if auth_failure_count > 0:
            failure_df = df[df['status'].str.contains('失敗', na=False)]
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
            self.log_output(f"時系列分析でエラー: {e}")
            stats['time_analysis'] = {
                'hourly_distribution': {},
                'daily_distribution': {},
                'weekday_distribution': {}
            }

        return stats

    def print_detailed_report(self, stats):
        """詳細レポートを表示（全件表示）"""
        self.log_output("\n" + "="*150)
        self.log_output("🔐 FORTIGATE SSL-VPN ログ分析 - 詳細レポート（全件表示）")
        self.log_output("="*150)

        # 基本統計
        self.log_output(f"\n📊 【基本統計】")
        self.log_output(f"{'項目':<25} {'値':<15} {'詳細'}")
        self.log_output("-" * 70)
        self.log_output(f"{'総ログエントリ数':<25} {stats['basic']['total_logs']:,}")
        self.log_output(f"{'認証成功(トンネル確立)':<25} {stats['basic']['auth_success']:,} ({stats['basic']['success_rate']:.1f}%)")
        self.log_output(f"{'認証失敗':<25} {stats['basic']['auth_failure']:,}")
        self.log_output(f"{'トンネル切断':<25} {stats['basic']['tunnel_down']:,}")
        self.log_output(f"{'総認証試行回数':<25} {stats['basic']['total_auth_attempts']:,}")
        self.log_output(f"{'ユニークユーザー数':<25} {stats['basic']['unique_users']:,}")
        self.log_output(f"{'ユニークIP数':<25} {stats['basic']['unique_ips']:,}")
        self.log_output(f"{'接続元国数':<25} {stats['basic']['unique_countries']:,}")

        # セッション統計
        if stats['sessions']['total_sessions'] > 0:
            self.log_output(f"\n⏱️  【セッション統計】")
            self.log_output(f"{'項目':<25} {'値'}")
            self.log_output("-" * 45)
            self.log_output(f"{'総セッション数':<25} {stats['sessions']['total_sessions']:,}")
            self.log_output(f"{'平均継続時間':<25} {stats['sessions']['avg_duration_minutes']:.1f}分")
            self.log_output(f"{'中央値継続時間':<25} {stats['sessions']['median_duration_minutes']:.1f}分")
            self.log_output(f"{'最長セッション':<25} {stats['sessions']['max_duration_hours']:.1f}時間")
            self.log_output(f"{'最短セッション':<25} {stats['sessions']['min_duration_minutes']:.1f}分")

        # 失敗理由統計（全件）
        if stats.get('failure_reasons'):
            self.log_output(f"\n🚨 【認証失敗理由】（全{len(stats['failure_reasons'])}件）")
            self.log_output(f"{'失敗理由':<50} {'件数':<10}")
            self.log_output("-" * 65)
            for reason, count in stats['failure_reasons'].items():
                self.log_output(f"{reason[:48]:<50} {count:<10}")

        # ユーザー別詳細（全件）
        if stats.get('user_details'):
            self.log_output(f"\n👥 【ユーザー別分析】（全{len(stats['user_details'])}名）")
            self.log_output(f"{'ユーザー名':<20} {'総ログ':<8} {'成功':<8} {'失敗':<8} {'成功率':<8} {'セッション':<8} {'平均時間':<10} {'IP数':<6} {'接続元国'}")
            self.log_output("-" * 140)

            for user in stats['user_details']:
                avg_session_str = f"{user['avg_session_minutes']:.1f}分" if user['avg_session_minutes'] > 0 else 'N/A'
                countries_display = user['countries'][:40] + '...' if len(user['countries']) > 40 else user['countries']
                self.log_output(f"{user['username']:<20} "
                              f"{user['total_logs']:<8} "
                              f"{user['success_count']:<8} "
                              f"{user['failure_count']:<8} "
                              f"{user['success_rate']:<7.1f}% "
                              f"{user['session_count']:<8} "
                              f"{avg_session_str:<10} "
                              f"{user['unique_ips']:<6} "
                              f"{countries_display}")

        # 国別詳細（全件）
        if stats.get('country_details'):
            self.log_output(f"\n🌍 【国別分析】（全{len(stats['country_details'])}カ国）")
            self.log_output(f"{'国名':<25} {'コード':<6} {'総ログ':<8} {'成功':<8} {'失敗':<8} {'成功率':<8} {'ユーザー':<8} {'IP数'}")
            self.log_output("-" * 95)

            for country in stats['country_details']:
                self.log_output(f"{country['country']:<25} "
                              f"{country['country_code']:<6} "
                              f"{country['total_logs']:<8} "
                              f"{country['success_count']:<8} "
                              f"{country['failure_count']:<8} "
                              f"{country['success_rate']:<7.1f}% "
                              f"{country['unique_users']:<8} "
                              f"{country['unique_ips']}")

        # セキュリティ警告（全件）
        if stats.get('ip_details'):
            suspicious_ips = [ip for ip in stats['ip_details'] if ip['is_suspicious']]
            if suspicious_ips:
                self.log_output(f"\n⚠️  【セキュリティ警告：疑わしいIP】（全{len(suspicious_ips)}件）")
                self.log_output(f"{'IPアドレス':<15} {'国名':<20} {'失敗':<6} {'失敗率':<8} {'対象ユーザー':<30} {'主な失敗理由'}")
                self.log_output("-" * 120)

                for ip in suspicious_ips:
                    users_display = ip['users_list'][:28] + '...' if len(ip['users_list']) > 28 else ip['users_list']
                    reasons_display = ip['failure_reasons'][:30] + '...' if len(ip['failure_reasons']) > 30 else ip['failure_reasons']
                    self.log_output(f"{ip['source_ip']:<15} "
                                  f"{ip['country']:<20} "
                                  f"{ip['failure_count']:<6} "
                                  f"{ip['failure_rate']:<7.1f}% "
                                  f"{users_display:<30} "
                                  f"{reasons_display}")
            else:
                self.log_output(f"\n✅ 【セキュリティ状況】")
                self.log_output("疑わしいIPアドレスは検出されませんでした。")

        # 全IP統計（参考情報）
        if stats.get('ip_details'):
            self.log_output(f"\n📋 【全IP統計】（全{len(stats['ip_details'])}件）")
            self.log_output(f"{'IPアドレス':<15} {'国名':<20} {'総ログ':<8} {'失敗':<6} {'失敗率':<8} {'ユーザー数':<8} {'初回':<12} {'最終'}")
            self.log_output("-" * 110)

            for ip in stats['ip_details']:
                self.log_output(f"{ip['source_ip']:<15} "
                              f"{ip['country']:<20} "
                              f"{ip['total_logs']:<8} "
                              f"{ip['failure_count']:<6} "
                              f"{ip['failure_rate']:<7.1f}% "
                              f"{ip['unique_users']:<8} "
                              f"{ip['first_seen'][:10]:<12} "
                              f"{ip['last_seen'][:10]}")

        self.log_output("\n" + "="*150)

    def save_text_report(self, output_dir):
        """コンソール出力をテキストファイルに保存"""
        report_path = f"{output_dir}/reports/analysis_report.txt"

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("Fortigate SSL-VPN ログ分析レポート\n")
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
            df.to_csv(f'{csv_dir}/01_ssl_vpn_all_logs.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 全ログデータ: {csv_dir}/01_ssl_vpn_all_logs.csv")

        # 2. セッション統計
        session_durations = self.calculate_connection_sessions()
        if session_durations:
            session_df = pd.DataFrame(session_durations)
            session_df.to_csv(f'{csv_dir}/02_connection_sessions.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 接続セッション: {csv_dir}/02_connection_sessions.csv")

        # 3. ユーザー統計（全件）
        if stats.get('user_details'):
            user_df = pd.DataFrame(stats['user_details'])
            user_df.to_csv(f'{csv_dir}/03_user_analysis_all.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 ユーザー分析（全件）: {csv_dir}/03_user_analysis_all.csv")

        # 4. 国別統計（全件）
        if stats.get('country_details'):
            country_df = pd.DataFrame(stats['country_details'])
            country_df.to_csv(f'{csv_dir}/04_country_analysis_all.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 国別分析（全件）: {csv_dir}/04_country_analysis_all.csv")

        # 5. IP別統計（全件）
        if stats.get('ip_details'):
            ip_df = pd.DataFrame(stats['ip_details'])
            ip_df.to_csv(f'{csv_dir}/05_ip_analysis_all.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 IP別分析（全件）: {csv_dir}/05_ip_analysis_all.csv")

        # 6. 疑わしいIP専用
        if stats.get('ip_details'):
            suspicious_ips = [ip for ip in stats['ip_details'] if ip['is_suspicious']]
            if suspicious_ips:
                suspicious_df = pd.DataFrame(suspicious_ips)
                suspicious_df.to_csv(f'{csv_dir}/06_suspicious_ips.csv', index=False, encoding='utf-8-sig')
                self.log_output(f"🚨 疑わしいIP: {csv_dir}/06_suspicious_ips.csv")

        # 7. 失敗理由統計（全件）
        if stats.get('failure_reasons'):
            failure_reasons_df = pd.DataFrame(list(stats['failure_reasons'].items()),
                                            columns=['失敗理由', '件数'])
            failure_reasons_df = failure_reasons_df.sort_values('件数', ascending=False)
            failure_reasons_df.to_csv(f'{csv_dir}/07_failure_reasons_all.csv', index=False, encoding='utf-8-sig')
            self.log_output(f"📄 失敗理由分析（全件）: {csv_dir}/07_failure_reasons_all.csv")

        # 8. 基本統計サマリー
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
    """GeoIPデータベースのセットアップガイド"""
    print("\n🌍 GeoIP データベースセットアップガイド（オプション）")
    print("="*60)
    print("GeoIPデータベースは補完用です。Fortigateログの srccountry を優先使用します。")
    print()
    print("1. MaxMind アカウント作成（無料）:")
    print("   https://www.maxmind.com/en/geolite2/signup")
    print()
    print("2. ライセンスキーを取得:")
    print("   ログイン後、Account → My License Key → Generate new license key")
    print()
    print("3. GeoLite2-City データベースをダウンロード:")
    print("   https://www.maxmind.com/en/accounts/current/geoip/downloads")
    print()
    print("4. 解凍してGeoLite2-City.mmdbファイルを取得")
    print("5. スクリプト実行時にパスを指定:")
    print("   python fortigate_analyzer.py -l logfile.log -g /path/to/GeoLite2-City.mmdb")
    print()

def print_help():
    """ヘルプメッセージを表示"""
    print("🔐 Fortigate SSL-VPN ログ分析ツール（全件対応版）")
    print("="*55)
    print()
    print("使用方法:")
    print("  python fortigate_analyzer.py -l <ログファイル> [オプション]")
    print()
    print("必須オプション:")
    print("  -l, --log-file <ファイルパス>    分析するFortigateログファイル")
    print("                                  (.gz圧縮ファイルにも対応)")
    print()
    print("オプション:")
    print("  -g, --geoip-db <ファイルパス>    MaxMind GeoLite2データベースファイル")
    print("                                  (Fortigateログの srccountry を優先使用)")
    print("  -h, --help                      このヘルプメッセージを表示")
    print()
    print("例:")
    print("  python fortigate_analyzer.py -l /var/log/fortigate.log")
    print("  python fortigate_analyzer.py -l fortigate.log.gz")
    print("  python fortigate_analyzer.py -l fortigate.log -g GeoLite2-City.mmdb")
    print()
    print("出力ファイル:")
    print("  - 専用フォルダ: fortigate_analysis_YYYYMMDD_HHMMSS/")
    print("  - テキストレポート: reports/analysis_report.txt")
    print("  - CSVデータ: csv_data/ フォルダ内（全件出力）")
    print()
    print("対応するログ形式:")
    print("  - SSL VPN login fail (logid=\"0101039426\")")
    print("  - SSL VPN tunnel up (logid=\"0101039947\") ← 認証成功")
    print("  - SSL VPN tunnel down (logid=\"0101039948\")")
    print("  - subtype=\"vpn\" を含むその他のSSL-VPNログ")
    print()
    print("特徴:")
    print("  - ユーザー、国、IP別統計は全件表示")
    print("  - 以前の分析結果を上書きしない専用フォルダ作成")
    print("  - コンソール出力をテキストファイルとしても保存")
    print("  - 他の分析でも使えるCSV形式での全データ出力")
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
        description='Fortigate SSL-VPN ログ分析ツール（全件対応版）',
        formatter_class=CustomHelpFormatter,
        add_help=False
    )

    parser.add_argument('--log-file', '-l',
                       help='分析するログファイルのパス（必須、.gzファイル対応）')
    parser.add_argument('--geoip-db', '-g',
                       help='GeoIP データベース(.mmdb)のパス（オプション、補完用）')
    parser.add_argument('--help', '-h', action='store_true',
                       help='ヘルプメッセージを表示')

    args = parser.parse_args()

    # ヘルプオプションまたは必須オプションが不足している場合
    if args.help or not args.log_file:
        print_help()
        if not args.log_file and not args.help:
            print("❌ エラー: ログファイルの指定が必要です (-l オプション)")
        return

    # ログファイルの存在確認
    if not os.path.exists(args.log_file):
        print(f"❌ エラー: ログファイル '{args.log_file}' が見つかりません")
        return

    # GeoIPデータベースの確認
    if args.geoip_db and not os.path.exists(args.geoip_db):
        print(f"⚠️  警告: GeoIPデータベース '{args.geoip_db}' が見つかりません")
        print("GeoIPデータベースなしで続行します...")
        args.geoip_db = None

    # ログアナライザーを初期化
    analyzer = SSLVPNLogAnalyzer(geoip_db_path=args.geoip_db)

    # 出力用専用フォルダを作成
    output_dir = analyzer.create_output_directory()

    analyzer.log_output(f"\n🔐 Fortigate SSL-VPN ログ分析を開始します（全件対応版）")
    analyzer.log_output(f"📁 ログファイル: {args.log_file}")
    analyzer.log_output(f"📂 出力フォルダ: {output_dir}")
    if args.geoip_db:
        analyzer.log_output(f"🌍 GeoIPデータベース: {args.geoip_db}")
    else:
        analyzer.log_output("💡 Fortigateログ内の srccountry フィールドを使用します")

    # ファイル形式の確認
    if args.log_file.endswith('.gz'):
        analyzer.log_output(f"📦 gzip圧縮ファイルとして処理します")

    # ログファイルを分析
    analyzer.analyze_log_file(args.log_file)

    if not analyzer.parsed_logs:
        analyzer.log_output("\n❌ SSL-VPN関連のログが見つかりませんでした")
        return

    # 詳細統計情報を生成
    stats = analyzer.generate_detailed_statistics()

    # 詳細レポートを表示（コンソール＋バッファ）
    analyzer.print_detailed_report(stats)

    # テキストレポートを保存
    analyzer.save_text_report(output_dir)

    # CSV出力（全件）
    analyzer.log_output(f"\n📊 分析結果をCSVファイルに出力中（全件）...")
    analyzer.export_all_csv(stats, output_dir)

    analyzer.log_output(f"\n✅ 分析が完了しました")
    analyzer.log_output(f"📂 すべての結果が以下のフォルダに保存されました:")
    analyzer.log_output(f"   {output_dir}/")
    analyzer.log_output(f"   ├── reports/analysis_report.txt （コンソール出力のテキスト版）")
    analyzer.log_output(f"   └── csv_data/ （全分析データCSV）")

if __name__ == "__main__":
    main()
