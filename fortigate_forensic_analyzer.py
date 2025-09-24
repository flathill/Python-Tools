#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fortigate SSL-VPN フォレンジック分析スクリプト

このスクリプトは、FortigateファイアウォールのSSL-VPNログを分析し、
セキュリティインシデントの調査やネットワーク利用状況の把握を支援します。

主な機能:
1. SSL-VPNログの解析と時系列分析
2. 宛先IP・サブネット分析（プライベート/グローバル分離）
3. 大容量通信の検出と分析
4. タイムライン分析機能
5. ジオロケーション分析（国別統計）
6. VPN割り当てIPアドレス追跡
7. ポート分析（2025年版：クラウドネイティブ対応）
8. 高リスクIP・サブネット検出
9. データ転送量分析とセッション統計
10. メモリ効率化されたストリーミング処理
11. 包括的なエラーハンドリング
12. 可読性の高いCSVレポート出力

特殊機能:
- 暗号通貨マイニング関連ポートの監視
- Kubernetes/Docker等コンテナ環境の監視
- 現代的な監視ツール（Prometheus、Grafana等）対応
- 大容量ログファイルのチャンク処理
- 組織固有の高リスクIP範囲設定

入力データ形式:
- Fortigate SSL-VPNログファイル（テキスト形式）
- 対応するログフォーマット: CEF、Key-Value形式
- 日時、ユーザー、送受信IP、ポート、バイト数等を含む

出力ファイル:
- subnet_analysis_private.csv: プライベートサブネット分析
- subnet_analysis_global.csv: グローバルサブネット分析  
- destination_ip_private.csv: プライベートIP詳細分析
- destination_ip_global.csv: グローバルIP詳細分析
- port_analysis.csv: ポート別接続統計
- timeline_analysis.csv: 時系列イベント分析
- data_transfer_analysis.csv: データ転送量統計
- geolocation_analysis.csv: 国別アクセス統計
- vpn_sessions.csv: VPNセッション詳細分析（新機能）
- vpn_user_summary.csv: VPNユーザー別サマリー（新機能）

使用方法:
基本的な使用:
    python fortigate_forensic_analyzer.py logfile.txt

特定ユーザーの分析:
    python fortigate_forensic_analyzer.py logfile.txt --user "username"

出力先指定:
    python fortigate_forensic_analyzer.py logfile.txt --output "/path/to/output"

大容量ファイル処理:
    python fortigate_forensic_analyzer.py logfile.txt --chunk-size 5000

コマンドライン引数:
    logfile.txt                 : 解析対象ログファイル（必須）
    --user, -u USER            : 対象ユーザー名（省略時：全ユーザー）
    --output, -o DIR           : 出力ディレクトリ（デフォルト：./forensic_output）
    --chunk-size, -c SIZE      : 読み込みチャンクサイズ（デフォルト：10,000行）

設定のカスタマイズ:
    ForensicConfigクラスで以下をカスタマイズ可能：
    - 監視対象ポート（CRITICAL_PORTS、ADMIN_PORTS等）
    - 高リスクIP範囲（HIGH_RISK_IP_RANGES）
    - 閾値設定（HIGH_VOLUME_THRESHOLD等）
    - パフォーマンス設定（DEFAULT_CHUNK_SIZE等）

実行例:
    # 基本分析
    python fortigate_forensic_analyzer.py /logs/fortigate.log
    
    # 特定ユーザーの詳細分析
    python fortigate_forensic_analyzer.py /logs/fortigate.log --user "john.doe"
    
    # 大容量ファイルの効率的処理
    python fortigate_forensic_analyzer.py /logs/large_fortigate.log --chunk-size 5000 --output /analysis/results

必要な依存関係:
    Python 3.6以上
    標準ライブラリのみ（追加インストール不要）

作成日: 2025年9月
バージョン: 8.0
最終更新: 2025年9月23日
"""

import re
import os
import csv
import logging
import traceback
import errno
from datetime import datetime
from collections import defaultdict
from ipaddress import ip_network, ip_address
from typing import Dict, List, Tuple, Any, Optional

# ログ設定
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ===================================================================
# 共通ユーティリティ関数
# ===================================================================
def seconds_to_duration_str(seconds: float) -> str:
    """秒数を時:分:秒形式の文字列に変換（共通関数）"""
    if seconds <= 0:
        return "0:00:00"
    
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    return f"{hours}:{minutes:02d}:{secs:02d}"


# ===================================================================
# 設定クラス - フォレンジック分析の全設定値をここで管理
# ===================================================================
class ForensicConfig:
    """
    Fortigate フォレンジック分析の設定値
    
    この設定を変更することで、分析対象や閾値をカスタマイズできます。
    変更後はスクリプトを再実行してください。
    """
    
    # ===== ネットワーク設定 =====
    # プライベートIPアドレス範囲（RFC1918 + ローカル）
    PRIVATE_IP_RANGES = [
        '10.0.0.0/8',        # クラスA プライベート
        '172.16.0.0/12',     # クラスB プライベート  
        '192.168.0.0/16',    # クラスC プライベート
        '127.0.0.0/8',       # ループバック
        '169.254.0.0/16'     # リンクローカル
    ]
    
    # 高リスクIPアドレス範囲（組織固有の要注意範囲）
    HIGH_RISK_IP_RANGES = [
        '172.16.0.0/16',     # 管理セグメント1
        '10.0.0.0/24'        # 管理セグメント2
    ]
    
    # 【重要度：最高】セキュリティクリティカルポート
    CRITICAL_PORTS = {
        # 従来の重要ポート（依然として高リスク）
        22: 'SSH',                    # セキュアシェル（最重要）
        3389: 'RDP',                  # リモートデスクトップ（リモートワーク増加）
        23: 'Telnet',                 # 非暗号化リモートアクセス（廃止推奨）
        21: 'FTP',                    # 非暗号化ファイル転送（廃止推奨）
        20: 'FTP-DATA',               # FTPデータ転送
        
        # データベース直接アクセス（高リスク）
        3306: 'MySQL',                # MySQL/MariaDB
        5432: 'PostgreSQL',           # PostgreSQL
        1433: 'MSSQL',               # Microsoft SQL Server
        1521: 'Oracle',              # Oracle Database
        27017: 'MongoDB',            # MongoDB
        6379: 'Redis',               # Redis（認証なしが危険）
        5984: 'CouchDB',             # CouchDB
        9042: 'Cassandra',           # Apache Cassandra
        
        # コンテナ・オーケストレーション（現代の重要ポート）
        2375: 'Docker-API',          # Docker API（非TLS）
        2376: 'Docker-TLS',          # Docker API（TLS）
        6443: 'Kubernetes-API',      # Kubernetes API Server
        10250: 'Kubelet',            # Kubernetes Kubelet
        2379: 'etcd',                # etcd（Kubernetesデータストア）
        2380: 'etcd-peer',           # etcd peer通信
        
        # リモートアクセス・管理
        5900: 'VNC',                 # VNCリモートアクセス
        5800: 'VNC-HTTP',            # VNC HTTP
        5985: 'WinRM-HTTP',          # Windows Remote Management
        5986: 'WinRM-HTTPS',         # Windows Remote Management (HTTPS)
        
        # 暗号通貨マイニング（セキュリティ要注意）
        4444: 'Stratum-Mining',      # 暗号通貨マイニングプール
        3333: 'Alt-Mining',          # 代替マイニングポート
    }
    
    # 【重要度：高】管理・運用ポート
    ADMIN_PORTS = {
        # Web・API管理
        80: 'HTTP',                   # 基本Webサーバー
        443: 'HTTPS',                 # セキュアWebサーバー（最重要）
        8080: 'HTTP-ALT',            # 代替HTTPポート
        8443: 'HTTPS-ALT',           # 代替HTTPSポート
        8000: 'HTTP-8000',           # 開発用Webサーバー
        3000: 'HTTP-3000',           # Node.js/React開発サーバー
        8888: 'HTTP-8888',           # Jupyter/代替Web
        
        # 現代の監視・可視化システム
        9090: 'Prometheus',          # メトリクス収集
        3000: 'Grafana',             # ダッシュボード・可視化
        9200: 'Elasticsearch',       # 検索・分析エンジン
        5601: 'Kibana',              # Elasticsearch可視化
        9243: 'Elasticsearch-SSL',   # Elasticsearch HTTPS
        
        # ログ・メッセージング
        5044: 'Logstash',            # ログ収集
        9092: 'Kafka',               # メッセージストリーミング
        2181: 'Zookeeper',           # 分散コーディネーション
        5672: 'RabbitMQ',            # メッセージキュー
        15672: 'RabbitMQ-Mgmt',      # RabbitMQ管理画面
        
        # サービスディスカバリ・設定管理
        8500: 'Consul',              # サービスディスカバリ
        8300: 'Consul-Server',       # Consulサーバー間通信
        4646: 'Nomad',               # ワークロードオーケストレーション
        8200: 'Vault',               # シークレット管理
        
        # 従来の管理プロトコル
        161: 'SNMP',                 # ネットワーク管理
        162: 'SNMP-TRAP',            # SNMPトラップ
        514: 'Syslog',               # システムログ
        1514: 'Syslog-TLS',          # セキュアSyslog
        
        # Windows管理
        135: 'RPC',                  # Windowsリモート手続き呼出
        139: 'NetBIOS',              # NetBIOSセッション
        445: 'SMB',                  # Server Message Block
        
        # CI/CD・開発ツール
        8081: 'Nexus',               # アーティファクトリポジトリ
        8082: 'SonarQube',           # コード品質管理
        9000: 'SonarQube-Alt',       # SonarQube代替ポート
        8084: 'Jenkins-Alt',         # Jenkins代替ポート
    }
    
    # 【重要度：標準】基本サービスポート
    STANDARD_PORTS = {
        # 基本ネットワークサービス
        53: 'DNS',                   # ドメインネームシステム
        67: 'DHCP-Server',           # DHCP（サーバー）
        68: 'DHCP-Client',           # DHCP（クライアント）
        123: 'NTP',                  # 時刻同期
        
        # 認証・ディレクトリサービス
        389: 'LDAP',                 # ディレクトリサービス
        636: 'LDAPS',                # セキュアLDAP
        88: 'Kerberos',              # Kerberos認証
        464: 'Kerberos-Pwd',         # Kerberosパスワード変更
        
        # メール関連
        25: 'SMTP',                  # メール送信
        110: 'POP3',                 # メール受信
        143: 'IMAP',                 # メール受信
        993: 'IMAPS',                # セキュアIMAP
        995: 'POP3S',                # セキュアPOP3
        587: 'SMTP-Submission',      # SMTP送信（認証付き）
        
        # ファイル共有
        2049: 'NFS',                 # Network File System
        111: 'Portmapper',           # RPCポートマッパー
        
        # 基本的なアプリケーション
        179: 'BGP',                  # Border Gateway Protocol
        1194: 'OpenVPN',             # VPNサーバー
        1723: 'PPTP',                # Point-to-Point Tunneling
    }
    
    # ===== 分析設定 =====
    # ファイル処理設定
    DEFAULT_CHUNK_SIZE = 10000              # ログファイル読み込みチャンクサイズ
    MAX_PROGRESS_DISPLAY_INTERVAL = 100000  # 進捗表示間隔
    
    # 分析閾値設定
    HIGH_VOLUME_THRESHOLD = 1000000000      # 大容量通信閾値（1GB）
    SUSPICIOUS_CONNECTION_THRESHOLD = 100    # 要注意接続数閾値
    HIGH_RISK_CONNECTION_THRESHOLD = 10     # 高リスク接続数閾値
    HIGH_RISK_IP_THRESHOLD = 5              # 高リスクIPアクセス閾値
    
    # CSV出力設定
    MAX_PORT_DISPLAY = 5                    # 上位ポート表示数
    MAX_COUNTRY_DISPLAY = 10                # 上位国表示数
    
    # ===== 設定変更ガイドライン =====
    """
    【設定変更ガイド】
    
    1. ネットワーク範囲の調整:
       - 組織のネットワーク構成に合わせてPRIVATE_IP_RANGESを調整
       - 監視対象の重要IPをHIGH_RISK_IP_RANGESに追加
       例: HIGH_RISK_IP_RANGES.append('192.168.100.0/24')
    
    2. ポート監視のカスタマイズ:
       - 組織で使用する特殊ポートをCRITICAL_PORTSに追加
       - 監視不要なポートは各辞書から削除
       例: CRITICAL_PORTS[9999] = 'Custom-Critical-Service'
    
    3. 閾値の調整:
       - 環境に応じてHIGH_VOLUME_THRESHOLDを調整
       - 小規模環境ではSUSPICIOUS_CONNECTION_THRESHOLDを下げる
    
    4. パフォーマンス調整:
       - 大容量ログ処理時はDEFAULT_CHUNK_SIZEを調整
       - メモリ制約環境では値を小さく設定（推奨: 1000-5000）
    
    【2025年版の主な変更点】
    - クラウドネイティブサービス対応（Kubernetes、Docker等）
    - 現代的な監視ツール対応（Prometheus、Grafana等）
    - データベース直接アクセスの重要視
    - 暗号通貨マイニング関連ポートの監視
    - CI/CD・DevOpsツールの対応
    """


# ===================================================================
# 以下、既存のクラス群（設定値を使用するよう変更）
# ===================================================================

class FortigateLogParser:
    """Fortigateログの解析"""

    def __init__(self):
        # 正規表現パターンを定義（VPN割り当てIP対応）
        self.field_patterns = {
            'user': r'user="([^"]*)"',
            'srcip': r'srcip=([\d.]+)',
            'dstip': r'dstip=([\d.]+)',
            'srcport': r'srcport=(\d+)',
            'dstport': r'dstport=(\d+)',
            'proto': r'proto=(\d+)',
            'sentbyte': r'sentbyte=(\d+)',
            'rcvdbyte': r'rcvdbyte=(\d+)',
            'duration': r'duration=(\d+)',
            'service': r'service="([^"]*)"',
            'action': r'action="([^"]*)"',
            'srccountry': r'srccountry="([^"]*)"',  # ジオロケーション用
            'dstcountry': r'dstcountry="([^"]*)"',  # ジオロケーション用
            'assignip': r'assignip=([\d.]+)',       # VPN割り当てIP用
            'ip': r'ip=([\d.]+)',                 # 代替IP表記
            'assigned_ip': r'assigned_ip=([\d.]+)', # 別表記
            'remoteip': r'remoteip=([\d.]+)',     # リモートIP
            'remip': r'remip=([\d.]+)',             # VPNリモートIP用（重要）
            'assignip_quoted': r'assignip="([\d.]+)"',  # クォート付きassignip
            'virtualip': r'virtualip=([\d.]+)',   # バーチャルIP
            'virtual_ip': r'virtual_ip=([\d.]+)', # バーチャルIP別表記
            'tunnelip': r'tunnelip=([\d.]+)',     # トンネルIP
            'tunnel': r'tunnel="([^"]*)"',          # トンネル情報
            'tunnelid': r'tunnelid=(\d+)',          # トンネルID
            'tunneltype': r'tunneltype="([^"]*)"',  # トンネルタイプ
            'policyid': r'policyid=(\d+)',          # ポリシーID
            'sessionid': r'sessionid=(\d+)',        # セッションID
            'group': r'group="([^"]*)"',            # ユーザーグループ
            'logdesc': r'logdesc="([^"]*)"',        # ログ説明
            'reason': r'reason="([^"]*)"',          # 理由・詳細
            'msg': r'msg="([^"]*)"',                # メッセージ
            'date': r'date=(\d{4}-\d{2}-\d{2})',
            'time': r'time=(\d{2}:\d{2}:\d{2})',
            'logid': r'logid="([^"]*)"',
            'type': r'type="([^"]*)"',
            'subtype': r'subtype="([^"]*)"',
            'level': r'level="([^"]*)"'
        }

    def parse_log_line(self, line: str) -> Dict[str, str]:
        """ログ行を解析してフィールド辞書を返す（VPNイベント対応）"""
        fields = {}
        for field, pattern in self.field_patterns.items():
            match = re.search(pattern, line)
            if match:
                fields[field] = match.group(1)
        
        # VPNイベントログの特別処理
        # remipがある場合はsrcipとしても扱う（VPN接続元IP）
        if 'remip' in fields and 'srcip' not in fields:
            fields['srcip'] = fields['remip']
        
        return fields

    def parse_logs(self, log_lines: List[str], target_user: str = None) -> List[Dict[str, str]]:
        """ログリストを解析"""
        parsed_logs = []
        for line in log_lines:
            if target_user and f'user="{target_user}"' not in line:
                continue

            fields = self.parse_log_line(line)
            if fields:
                parsed_logs.append(fields)

        if target_user:
            logger.info(f"解析したログ数 (ユーザ: {target_user}): {len(parsed_logs)}件")
        else:
            logger.info(f"解析したログ数 (全てのユーザ): {len(parsed_logs)}件")
        return parsed_logs

class IPAnalyzer:
    """IP分析器（プライベート/グローバル分離対応・設定外部化対応）"""

    def __init__(self, config: ForensicConfig = None):
        self.config = config or ForensicConfig()
        
        # 設定からプライベートIPレンジを取得
        self.private_ranges = [
            ip_network(range_str) for range_str in self.config.PRIVATE_IP_RANGES
        ]

        # 設定から高リスクIPレンジを取得
        self.high_risk_ranges = [
            ip_network(range_str) for range_str in self.config.HIGH_RISK_IP_RANGES
        ]

    def is_private_ip(self, ip_str: str) -> bool:
        """プライベートIPかどうか判定"""
        try:
            ip = ip_address(ip_str)
            return any(ip in network for network in self.private_ranges)
        except:
            return False

    def is_high_risk_ip(self, ip_str: str) -> bool:
        """高リスクIPかどうか判定"""
        try:
            ip = ip_address(ip_str)
            return any(ip in network for network in self.high_risk_ranges)
        except:
            return False

    def get_subnet(self, ip_str: str, prefix_length: int = 24) -> str:
        """IPアドレスからサブネットを取得"""
        try:
            ip = ip_address(ip_str)
            if self.is_private_ip(ip_str):
                # プライベートIPは/24で集約
                network = ip_network(f"{ip}/{prefix_length}", strict=False)
            else:
                # グローバルIPは/16で集約
                network = ip_network(f"{ip}/16", strict=False)
            return str(network)
        except:
            return "unknown"

class GeolocationAnalyzer:
    """ジオロケーション分析器（設定外部化対応）"""

    def __init__(self, config: ForensicConfig = None):
        self.config = config or ForensicConfig()
        
        # 設定から閾値を取得
        self.high_risk_connection_threshold = self.config.HIGH_RISK_CONNECTION_THRESHOLD
        self.high_risk_ip_threshold = self.config.HIGH_RISK_IP_THRESHOLD

    def analyze_country_stats(self, parsed_logs: List[Dict[str, str]]) -> Dict[str, Dict]:
        """国別統計を分析"""
        country_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ips': set(),
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
        })

        for log in parsed_logs:
            # 送信元国情報
            src_country = log.get('srccountry', 'Unknown')
            if src_country and src_country != 'Unknown':
                country_stats[src_country]['connection_count'] += 1
                if 'srcip' in log:
                    country_stats[src_country]['unique_ips'].add(log['srcip'])
                if 'sentbyte' in log:
                    country_stats[src_country]['total_bytes_sent'] += int(log.get('sentbyte', 0))
                if 'rcvdbyte' in log:
                    country_stats[src_country]['total_bytes_received'] += int(log.get('rcvdbyte', 0))

            # 宛先国情報
            dst_country = log.get('dstcountry', 'Unknown')
            if dst_country and dst_country != 'Unknown' and dst_country != src_country:
                country_stats[dst_country]['connection_count'] += 1
                if 'dstip' in log:
                    country_stats[dst_country]['unique_ips'].add(log['dstip'])

        # setをリストに変換
        result = {}
        for country, stats in country_stats.items():
            stats['unique_ips'] = list(stats['unique_ips'])
            stats['unique_ip_count'] = len(stats['unique_ips'])
            result[country] = stats

        return result

class VPNSessionAnalyzer:
    """VPNセッション専用分析器（VPN接続情報の詳細分析）"""

    def __init__(self, config: ForensicConfig = None):
        self.config = config or ForensicConfig()
        # セッション分割の閾値（秒）- デフォルト30分
        self.session_gap_threshold = 1800  # 30分 = 1800秒

    def analyze_vpn_sessions(self, parsed_logs: List[Dict[str, str]]) -> Dict:
        """VPNセッション情報を詳細分析（VPNイベントベース + IPマッピング）"""
        vpn_sessions = defaultdict(lambda: {
            'user': '',
            'srcip': '',  # 実際のクライアントIP
            'assignip': '',  # VPN割り当てIP
            'tunnel_id': '',  # トンネルID（重要）
            'session_start': None,  # tunnel-up時刻
            'session_end': None,    # tunnel-down時刻
            'session_duration_seconds': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'total_bytes_transfer': 0,
            'connection_count': 0,
            'unique_destinations': set(),
            'countries': set(),
            'tunnel_info': '',
            'tunnel_type': '',
            'user_group': '',
            'policy_id': '',
            'actions': set(),
            'services': set(),
            'vpn_events': [],  # VPNイベント履歴
            'connection_reason': set(),
            'traffic_events': [],  # トラフィックイベント
            'session_status': 'unknown'  # active, closed, unknown
        })

        user_summary = defaultdict(lambda: {
            'total_sessions': 0,
            'active_sessions': 0,
            'closed_sessions': 0,
            'total_bytes_transfer': 0,
            'unique_source_ips': set(),
            'unique_assign_ips': set(),
            'countries': set(),
            'first_connection': None,
            'last_connection': None,
            'avg_session_duration': 0,
            'total_session_duration': 0
        })

        # IPマッピングテーブル (外部IP -> VPN割り当てIP)
        ip_mapping_table = {}  # {(user, external_ip): internal_ip}
        session_mapping_table = {}  # {(user, external_ip, tunnel_id): internal_ip}
        active_sessions_timeline = {}  # {(user, internal_ip): [(start_time, end_time, session_key)]}
        detailed_mapping = []  # [(user, external_ip, internal_ip, start_time, end_time, tunnel_id, session_key)]

        logger.info("VPNセッション分析を開始（VPNイベントベース + IPマッピング）...")

        # まずVPNイベントログ（tunnel-up/down）を抽出・分析してIPマッピングを構築
        vpn_events = []
        traffic_logs = []
        
        for log in parsed_logs:
            log_type = log.get('type', '')
            subtype = log.get('subtype', '')
            action = log.get('action', '')
            
            # VPNイベントログの判定
            if (log_type == 'event' and subtype == 'vpn') or ('tunnel' in action.lower()):
                vpn_events.append(log)
            else:
                # トラフィックログ
                traffic_logs.append(log)
        
        logger.info(f"VPNイベントログ: {len(vpn_events)}件、トラフィックログ: {len(traffic_logs)}件")

        # VPNイベントログを時刻順にソートしてIPマッピング構築
        sorted_vpn_events = []
        for log in vpn_events:
            try:
                if 'date' in log and 'time' in log:
                    datetime_str = f"{log['date']} {log['time']}"
                    dt = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
                    log['parsed_datetime'] = dt
                    sorted_vpn_events.append(log)
            except ValueError:
                continue
        
        sorted_vpn_events.sort(key=lambda x: x['parsed_datetime'])
        
        # IPマッピングテーブルの構築
        logger.info("詳細IPマッピングテーブルを構築中...")
        for event in sorted_vpn_events:
            user = event.get('user', '')
            srcip = event.get('srcip', '') or event.get('remip', '')  # 外部IP
            action = event.get('action', '').lower()
            event_time = event['parsed_datetime']
            tunnel_id = event.get('tunnelid', '')
            
            # assignipの取得（複数フィールドを試行・ip除外）
            assign_ip = (event.get('assignip') or 
                        event.get('assignip_quoted') or
                        event.get('assigned_ip') or 
                        event.get('virtualip') or
                        event.get('virtual_ip') or
                        event.get('tunnelip', ''))
            # 注意: 'ip'や'remoteip'は外部IPの可能性があるため除外
            
            # 手動デバッグ: 1204628915セッション
            if tunnel_id == '1204628915':
                logger.warning(f"[assignip調査] tunnel:1204628915のマッピング登録: "
                             f"user:{user}, external:{srcip}, internal:{assign_ip}, "
                             f"開始時刻:{event_time}, tunnel:{tunnel_id}")
                logger.warning(f"[assignip詳細] 利用可能フィールド: "
                             f"assignip:{event.get('assignip')}, "
                             f"assigned_ip:{event.get('assigned_ip')}, "
                             f"virtualip:{event.get('virtualip')}, "
                             f"ip:{event.get('ip')} (除外)")
            
            if user and srcip and assign_ip:
                if 'tunnel-up' in action or 'login' in action:
                    # セッション固有マッピング
                    if tunnel_id:
                        session_key_for_mapping = (user, srcip, tunnel_id)
                        session_mapping_table[session_key_for_mapping] = assign_ip
                    
                    # 詳細マッピングエントリを追加
                    mapping_entry = {
                        'user': user,
                        'external_ip': srcip,
                        'internal_ip': assign_ip,
                        'start_time': event_time,
                        'end_time': None,  # tunnel-downで設定
                        'tunnel_id': tunnel_id,
                        'session_key': f"{user}_tunnel_{tunnel_id}" if tunnel_id else None
                    }
                    detailed_mapping.append(mapping_entry)
                    
                    # ゼロ接続セッションの調査用ログ
                    if tunnel_id == '1204628915':
                        logger.warning(f"[ゼロ接続調査] fom_tunnel_1204628915のマッピング登録: "
                                     f"user:{user}, external:{srcip}, internal:{assign_ip}, "
                                     f"開始時刻:{event_time}, tunnel:{tunnel_id}")
                    
                    # アクティブセッション管理
                    timeline_key = (user, assign_ip)
                    if timeline_key not in active_sessions_timeline:
                        active_sessions_timeline[timeline_key] = []
                    
                    logger.debug(f"IPマッピング登録(開始): {user} {srcip} -> {assign_ip} [{tunnel_id}] ({event_time})")
                    
                elif 'tunnel-down' in action or 'logout' in action:
                    # 終了時刻を設定
                    for mapping in reversed(detailed_mapping):  # 最新から検索
                        if (mapping['user'] == user and 
                            mapping['external_ip'] == srcip and 
                            mapping['tunnel_id'] == tunnel_id and 
                            mapping['end_time'] is None):
                            mapping['end_time'] = event_time
                            
                            # ゼロ接続セッションの調査用ログ
                            if tunnel_id == '1204628915':
                                logger.warning(f"[ゼロ接続調査] fom_tunnel_1204628915のマッピング終了: "
                                             f"期間:{mapping['start_time']} - {event_time}, "
                                             f"duration:{(event_time - mapping['start_time']).total_seconds()}秒")
                            
                            # タイムライン更新
                            timeline_key = (user, mapping['internal_ip'])
                            if timeline_key in active_sessions_timeline:
                                active_sessions_timeline[timeline_key].append(
                                    (mapping['start_time'], event_time, mapping['session_key'])
                                )
                            
                            logger.debug(f"IPマッピング終了: {user} {srcip} -> {mapping['internal_ip']} [{tunnel_id}] ({event_time})")
                            break
        
        # 終了していないセッションの処理
        for mapping in detailed_mapping:
            if mapping['end_time'] is None:
                # 現在時刻またはログの最終時刻を終了時刻とする
                mapping['end_time'] = sorted_vpn_events[-1]['parsed_datetime'] if sorted_vpn_events else datetime.now()
                
                timeline_key = (mapping['user'], mapping['internal_ip'])
                if timeline_key in active_sessions_timeline:
                    active_sessions_timeline[timeline_key].append(
                        (mapping['start_time'], mapping['end_time'], mapping['session_key'])
                    )
        
        logger.info(f"詳細IPマッピングテーブル構築完了: {len(detailed_mapping)}エントリ")
        logger.info(f"アクティブセッション管理: {len(active_sessions_timeline)}タイムライン")
        
        # VPNイベントログからセッションを構築
        for event in sorted_vpn_events:
            user = event.get('user', '')
            srcip = event.get('srcip', '') or event.get('remip', '')  # remipも考慮
            tunnel_id = event.get('tunnelid', '')
            action = event.get('action', '').lower()
            event_time = event['parsed_datetime']
            
            # 手動デバッグ: 1204628915セッションの生ログ表示
            if tunnel_id == '1204628915':
                logger.warning(f"[生ログ調査] tunnel:1204628915のVPNイベント詳細:")
                logger.warning(f"  Raw event keys: {list(event.keys())}")
                # assignip関連フィールドのみを表示
                ip_fields = ['assignip', 'assigned_ip', 'virtualip', 'virtual_ip', 'tunnelip']
                external_ip_fields = ['ip', 'remoteip', 'remip', 'srcip']  # 外部IP系
                
                logger.warning(f"  === 内部IP系フィールド ===")
                for key in ip_fields:
                    if key in event:
                        logger.warning(f"  {key}: {event[key]}")
                        
                logger.warning(f"  === 外部IP系フィールド（参考） ===")
                for key in external_ip_fields:
                    if key in event:
                        logger.warning(f"  {key}: {event[key]}")
            
            if not (user and tunnel_id):
                continue
            
            # セッションキー: ユーザー + トンネルID（最も確実）
            session_key = f"{user}_tunnel_{tunnel_id}"
            
            session = vpn_sessions[session_key]
            
            # 基本情報の設定
            session['user'] = user
            session['srcip'] = srcip or session['srcip']
            session['tunnel_id'] = tunnel_id
            
            # VPNイベントの処理
            if 'tunnel-up' in action or 'login' in action:
                session['session_start'] = event_time
                session['session_status'] = 'active'
                
                # assignipの取得（複数フィールドを試行・ip除外）
                assign_ip = (event.get('assignip') or 
                           event.get('assignip_quoted') or
                           event.get('assigned_ip') or 
                           event.get('virtualip') or
                           event.get('virtual_ip') or
                           event.get('tunnelip') or
                           session.get('assignip', ''))
                # 注意: 'ip'や'remoteip'は外部IPの可能性があるため除外
                
                if assign_ip:
                    session['assignip'] = assign_ip
                    
                    # 手動デバッグ: 1204628915セッション
                    if tunnel_id == '1204628915':
                        logger.warning(f"[assignip調査] fom_tunnel_1204628915のassignip設定: "
                                     f"assign_ip:{assign_ip}, event詳細: "
                                     f"assignip:{event.get('assignip')}, "
                                     f"assigned_ip:{event.get('assigned_ip')}, "
                                     f"virtualip:{event.get('virtualip')}")
                else:
                    # assignipが見つからない場合の警告
                    if tunnel_id == '1204628915':
                        logger.warning(f"[assignip調査] fom_tunnel_1204628915でassignip未発見: "
                                     f"利用可能フィールド: {list(event.keys())}")
                                     
                session['tunnel_type'] = event.get('tunneltype', '') or session['tunnel_type']
                session['user_group'] = event.get('group', '') or session['user_group']
                session['connection_reason'].add(event.get('reason', 'login'))
                
            elif 'tunnel-down' in action or 'logout' in action:
                session['session_end'] = event_time
                session['session_status'] = 'closed'
                session['connection_reason'].add(event.get('reason', 'logout'))
            
            # 地理情報
            if event.get('srccountry'):
                session['countries'].add(event['srccountry'])
            
            # その他の情報
            if event.get('tunnel'):
                session['tunnel_info'] = event['tunnel']
            if event.get('policyid'):
                session['policy_id'] = event['policyid']
            
            session['actions'].add(action)
            session['vpn_events'].append({
                'timestamp': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                'action': action,
                'reason': event.get('reason', ''),
                'message': event.get('msg', '')
            })
        
        logger.info(f"VPNイベントからセッション構築: {len(vpn_sessions)}セッション")
        
        # トラフィックログをVPNセッションに関連付け（IPマッピング使用）
        logger.info("IPマッピングテーブルを使用してトラフィックログを関連付け...")
        matched_traffic = 0
        unmatched_traffic = 0
        
        def find_mapped_session(traffic_user, traffic_srcip, traffic_time):
            """詳細IPマッピングテーブルを使用してセッションを検索"""
            best_match = None
            best_confidence = 0
            match_details = []
            
            # ゼロ接続セッション調査用の詳細ログ
            is_target_investigation = traffic_user == 'fom' and traffic_srcip == '172.111.131.228'
            
            # 1. 時間範囲内での完全マッチ検索
            for mapping in detailed_mapping:
                if mapping['user'] == traffic_user:
                    confidence = 0
                    match_reason = []
                    
                    # 外部IP完全一致
                    if mapping['external_ip'] == traffic_srcip:
                        confidence += 100
                        match_reason.append(f"External IP Match ({traffic_srcip})")
                    # 内部IP完全一致（逆引き）
                    elif mapping['internal_ip'] == traffic_srcip:
                        confidence += 95
                        match_reason.append(f"Internal IP Match ({traffic_srcip})")
                    else:
                        continue  # IP不一致の場合はスキップ
                    
                    # 時間範囲チェック
                    if mapping['start_time'] <= traffic_time <= mapping['end_time']:
                        confidence += 50
                        match_reason.append("Within Time Range")
                    elif abs((traffic_time - mapping['start_time']).total_seconds()) <= 300:  # 5分以内
                        confidence += 20
                        match_reason.append("Near Start Time")
                    elif abs((traffic_time - mapping['end_time']).total_seconds()) <= 300:  # 5分以内
                        confidence += 15
                        match_reason.append("Near End Time")
                    
                    if confidence > best_confidence:
                        best_confidence = confidence
                        # 対応するVPNセッションを検索
                        target_internal_ip = mapping['internal_ip']
                        session_key_to_find = mapping['session_key']
                        
                        # ゼロ接続セッション調査
                        if is_target_investigation:
                            logger.debug(f"[ゼロ接続調査] マッピング候補発見: tunnel:{mapping['tunnel_id']}, "
                                       f"confidence:{confidence}, session_key:{session_key_to_find}, "
                                       f"期間:{mapping['start_time']} - {mapping['end_time']}, "
                                       f"トラフィック時刻:{traffic_time}")
                        
                        for session_key, session in vpn_sessions.items():
                            if (session_key == session_key_to_find or
                                (session['user'] == traffic_user and 
                                 session.get('assignip') == target_internal_ip and
                                 session.get('tunnel_id') == mapping['tunnel_id'])):
                                best_match = session
                                match_details = match_reason
                                
                                # ゼロ接続セッション調査
                                if is_target_investigation and session_key == 'fom_tunnel_1204628915':
                                    logger.warning(f"[ゼロ接続調査] fom_tunnel_1204628915にマッチ候補: "
                                                 f"confidence:{confidence}, 理由:{match_reason}")
                                break
            
            # 2. セッション固有マッピングでの検索
            if best_confidence < 100:  # 完全マッチでない場合
                for session_key, session in vpn_sessions.items():
                    if session['user'] == traffic_user:
                        tunnel_id = session.get('tunnel_id', '')
                        external_ip = session.get('srcip', '')
                        
                        session_mapping_key = (traffic_user, traffic_srcip, tunnel_id)
                        if session_mapping_key in session_mapping_table:
                            target_assign_ip = session_mapping_table[session_mapping_key]
                            if session.get('assignip') == target_assign_ip:
                                confidence = 90
                                best_match = session
                                match_details = [f"Session-Specific Mapping ({traffic_srcip}->{target_assign_ip})"]
                                best_confidence = confidence
                                break
            
            # 3. アクティブセッションタイムラインでの検索
            if best_confidence < 90:
                timeline_key = (traffic_user, traffic_srcip)
                if timeline_key in active_sessions_timeline:
                    for start_time, end_time, session_key in active_sessions_timeline[timeline_key]:
                        if start_time <= traffic_time <= end_time:
                            for sk, session in vpn_sessions.items():
                                if sk == session_key:
                                    confidence = 85
                                    best_match = session
                                    match_details = [f"Timeline Match ({start_time}-{end_time})"]
                                    best_confidence = confidence
                                    break
            
            if best_match:
                # ゼロ接続セッション調査
                if is_target_investigation:
                    session_key = None
                    for sk, session in vpn_sessions.items():
                        if session == best_match:
                            session_key = sk
                            break
                    logger.debug(f"[ゼロ接続調査] 最終マッチ結果: {session_key}, "
                               f"confidence:{best_confidence}%, 詳細:{match_details}")
                
                return best_match, f"Detailed Mapping [Confidence {best_confidence}%] ({'+'.join(match_details)})"
            else:
                # ゼロ接続セッション調査
                if is_target_investigation:
                    logger.warning(f"[ゼロ接続調査] トラフィック未マッチ: {traffic_user} {traffic_srcip} {traffic_time}")
                
                return None, "Detailed Mapping Not Found"
        
        for log in traffic_logs:
            user = log.get('user')
            srcip = log.get('srcip')
            # assignipを複数フィールドから取得
            assignip = (log.get('assignip') or 
                       log.get('ip') or 
                       log.get('assigned_ip') or 
                       log.get('remoteip', ''))
            
            if not (user and srcip):
                continue
            
            # 時刻情報の処理
            try:
                if 'date' in log and 'time' in log:
                    datetime_str = f"{log['date']} {log['time']}"
                    current_time = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
                else:
                    continue
            except ValueError:
                continue
            
            # IPマッピングテーブルを使用してセッション検索
            matching_session, match_reason = find_mapped_session(user, srcip, current_time)
            
            # ゼロ接続セッションの調査用デバッグ
            if user == 'fom' and srcip == '172.111.131.228':
                logger.debug(f"[ゼロ接続調査] fom+172.111.131.228のトラフィック: "
                           f"時刻:{current_time}, マッチ結果:{matching_session['session_key'] if matching_session else 'None'}, "
                           f"理由:{match_reason}")
                           
                # fom_tunnel_1204628915との時間重複確認
                target_session = vpn_sessions.get('fom_tunnel_1204628915')
                if target_session and target_session.get('session_start') and target_session.get('session_end'):
                    start_time = target_session['session_start']
                    end_time = target_session['session_end']
                    if start_time <= current_time <= end_time:
                        logger.warning(f"[ゼロ接続調査] fom_tunnel_1204628915の時間内トラフィック検出: "
                                     f"{current_time} (セッション: {start_time} - {end_time}) "
                                     f"しかし関連付け先: {matching_session['session_key'] if matching_session else 'None'}")
            
            # マッピングテーブルで見つからない場合は従来の方法
            if matching_session is None:
                matching_session, fallback_reason = self._find_session_by_similarity(
                    vpn_sessions, user, srcip, assignip, current_time)
                if matching_session:
                    match_reason = f"Similarity Match ({fallback_reason})"
            
            # セッションが見つからない場合、推測でセッションを作成
            if matching_session is None:
                # トラフィックベースの推測セッション作成
                session_key = f"{user}_traffic_{srcip}_{assignip or 'unknown'}"
                session = vpn_sessions[session_key]
                session['user'] = user
                session['srcip'] = srcip
                session['assignip'] = assignip or 'unknown'
                session['session_status'] = 'inferred'  # 推測セッション
                if session['session_start'] is None:
                    session['session_start'] = current_time
                matching_session = session
                match_reason = "New Inferred Session"
                unmatched_traffic += 1
                
                # 推測セッションの詳細分析
                if srcip == assignip or assignip == 'unknown':
                    if srcip and srcip.startswith(('10.', '172.16.', '192.168.')):
                        # 内部IPアドレスからの直接アクセスの可能性
                        session['inferred_reason'] = 'Internal Network Direct Access'
                        logger.debug(f"[推測セッション] 内部IP直接アクセス検出: {user}@{srcip}")
                    else:
                        session['inferred_reason'] = 'Missing VPN Events (External IP)'
                        logger.debug(f"[推測セッション] VPNイベント欠落: {user}@{srcip}")
                else:
                    session['inferred_reason'] = 'Missing VPN Events (IP Mismatch)'
                    logger.debug(f"[推測セッション] IP不一致: {user} {srcip}!={assignip}")
            else:
                matched_traffic += 1
            
            # トラフィック情報をセッションに追加
            if matching_session:
                matching_session['connection_count'] += 1
                
                # バイト数の処理
                sent_bytes = int(log.get('sentbyte', 0) or 0)
                received_bytes = int(log.get('rcvdbyte', 0) or 0)
                matching_session['total_bytes_sent'] += sent_bytes
                matching_session['total_bytes_received'] += received_bytes
                matching_session['total_bytes_transfer'] += sent_bytes + received_bytes
                
                # 宛先情報
                dstip = log.get('dstip')
                if dstip:
                    matching_session['unique_destinations'].add(dstip)
                
                # 地理情報
                if log.get('dstcountry'):
                    matching_session['countries'].add(log['dstcountry'])
                
                # サービス・ポート情報
                service = log.get('service')
                if service:
                    matching_session['services'].add(service)
                
                # アクション
                action = log.get('action')
                if action:
                    matching_session['actions'].add(action)
                
                # トラフィックイベント記録
                matching_session['traffic_events'].append({
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'dstip': dstip,
                    'service': service,
                    'action': action,
                    'bytes': sent_bytes + received_bytes,
                    'match_reason': match_reason
                })
                
                if matched_traffic <= 10:  # 最初の10件はデバッグ表示
                    logger.debug(f"トラフィック関連付け: {user} {srcip} -> {match_reason}")
        
        logger.info(f"トラフィック関連付け結果: マッチ={matched_traffic}, 未マッチ={unmatched_traffic}")
        logger.info(f"詳細マッピング効果: {len(detailed_mapping)}エントリ使用")
        
        # セッション別トラフィック統計の表示
        logger.info("セッション別トラフィック統計:")
        session_stats = []
        for session_key, session in vpn_sessions.items():
            if session['connection_count'] > 0:
                session_stats.append({
                    'key': session_key,
                    'user': session['user'],
                    'srcip': session.get('srcip', ''),
                    'assignip': session.get('assignip', ''),
                    'tunnel_id': session.get('tunnel_id', ''),
                    'connections': session['connection_count'],
                    'bytes': session['total_bytes_transfer'],
                    'status': session.get('session_status', 'unknown')
                })
        
        # 接続数でソート
        session_stats.sort(key=lambda x: x['connections'], reverse=True)
        
        for i, stat in enumerate(session_stats[:10]):  # 上位10セッション
            logger.info(f"  #{i+1}: {stat['key']} - {stat['user']} "
                       f"[{stat['srcip']}->{stat['assignip']}] "
                       f"tunnel:{stat['tunnel_id']} - {stat['connections']}接続, "
                       f"{stat['bytes']:,}bytes, {stat['status']}")
        
        if len(session_stats) > 10:
            logger.info(f"  ... 他{len(session_stats) - 10}セッション")
        
        # 同一ユーザーの複数セッション警告
        user_sessions = {}
        for session_key, session in vpn_sessions.items():
            if session['connection_count'] > 0:
                user = session['user']
                if user not in user_sessions:
                    user_sessions[user] = []
                user_sessions[user].append({
                    'key': session_key,
                    'connections': session['connection_count'],
                    'assignip': session.get('assignip', ''),
                    'tunnel_id': session.get('tunnel_id', ''),
                    'status': session.get('session_status', 'unknown'),
                    'bytes': session['total_bytes_transfer']
                })
        
        multi_session_users = {u: sessions for u, sessions in user_sessions.items() if len(sessions) > 1}
        if multi_session_users:
            logger.warning(f"複数セッション持ちユーザー: {len(multi_session_users)}名")
            for user, sessions in multi_session_users.items():
                total_connections = sum(s['connections'] for s in sessions)
                total_bytes = sum(s['bytes'] for s in sessions)
                vpn_sessions_count = len([s for s in sessions if s['tunnel_id']])
                inferred_sessions_count = len([s for s in sessions if not s['tunnel_id']])
                
                logger.warning(f"  {user}: {len(sessions)}セッション(VPN:{vpn_sessions_count}, 推測:{inferred_sessions_count}), "
                             f"総接続数{total_connections:,}, 総通信量{total_bytes:,}bytes")
                for session in sessions:
                    logger.warning(f"    - {session['key']}: {session['connections']:,}接続, "
                                 f"{session['bytes']:,}bytes, assignip:{session['assignip']}, "
                                 f"tunnel:{session['tunnel_id']}, status:{session['status']}")
                
                # セッション間のバランスチェック
                if len(sessions) > 1:
                    max_connections = max(s['connections'] for s in sessions)
                    min_connections = min(s['connections'] for s in sessions)
                    if max_connections > 0 and min_connections / max_connections < 0.01:  # 1%未満のセッション
                        small_sessions = [s for s in sessions if s['connections'] / max_connections < 0.01]
                        logger.info(f"    [分析] 少数接続セッション{len(small_sessions)}個検出 - 正常な時系列分離と推測")
        else:
            logger.info("複数セッションユーザーなし - 単純なセッション構成")
        
        # 推測セッション分析
        inferred_sessions = {k: v for k, v in vpn_sessions.items() 
                           if v.get('session_status') == 'inferred' and v.get('connection_count', 0) > 0}
        
        if inferred_sessions:
            logger.warning(f"推測セッション検出: {len(inferred_sessions)}個")
            for session_key, session in inferred_sessions.items():
                reason = session.get('inferred_reason', 'Unknown')
                connections = session.get('connection_count', 0)
                bytes_total = session.get('total_bytes_transfer', 0)
                srcip = session.get('srcip', '')
                assignip = session.get('assignip', '')
                
                logger.warning(f"  {session_key}: {connections:,}接続, {bytes_total:,}bytes")
                logger.warning(f"    理由: {reason}")
                logger.warning(f"    IP情報: src={srcip}, assign={assignip}")
                
                # 内部IP直接アクセスの詳細分析
                if reason == 'Internal Network Direct Access':
                    destinations = list(session.get('unique_destinations', set()))[:5]
                    logger.info(f"    接続先: {', '.join(destinations)}")
                    logger.info(f"    → VPN経由ではない内部ネットワーク通信の可能性")
        else:
            logger.info("推測セッションなし - 全トラフィックがVPNイベントと関連付け完了")
        
        # 擬陽性検出レポート
        logger.info("擬陽性リスク分析...")
        risk_sessions = []
        for session_key, session in vpn_sessions.items():
            if session['connection_count'] > 0:
                # リスク要因の計算
                risk_factors = []
                risk_score = 0
                
                # 同一ユーザーの複数セッション
                user_sessions = [s for s in vpn_sessions.values() if s['user'] == session['user']]
                if len(user_sessions) > 1:
                    risk_factors.append("複数セッション存在")
                    risk_score += 10
                
                # assignipが空の場合
                if not session.get('assignip'):
                    risk_factors.append("assignip未設定")
                    risk_score += 15
                
                # セッション時間外のトラフィック比率
                if session.get('traffic_events'):
                    out_of_session_events = 0
                    for event in session['traffic_events']:
                        event_time = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
                        session_start = session.get('session_start')
                        session_end = session.get('session_end')
                        if session_start and session_end:
                            if not (session_start <= event_time <= session_end):
                                out_of_session_events += 1
                    
                    if out_of_session_events > 0:
                        out_ratio = out_of_session_events / len(session['traffic_events'])
                        if out_ratio > 0.3:  # 30%以上が時間外
                            risk_factors.append(f"時間外トラフィック{out_ratio:.1%}")
                            risk_score += 20
                
                if risk_score > 20:  # 中リスク以上
                    risk_sessions.append({
                        'session_key': session_key,
                        'user': session['user'],
                        'risk_score': risk_score,
                        'risk_factors': risk_factors,
                        'connection_count': session['connection_count'],
                        'total_bytes': session['total_bytes_transfer']
                    })
        
        if risk_sessions:
            logger.warning(f"擬陽性リスクのあるセッション: {len(risk_sessions)}件")
            for risk in sorted(risk_sessions, key=lambda x: x['risk_score'], reverse=True)[:5]:
                logger.warning(f"  {risk['session_key']}: リスク={risk['risk_score']}, "
                             f"要因={risk['risk_factors']}, 接続数={risk['connection_count']}")
        else:
            logger.info("高リスクな擬陽性は検出されませんでした")
            
        logger.info("セッション継続時間を計算...")
        
        # セッション継続時間とユーザーサマリーの計算
        for session_key, session in vpn_sessions.items():
            user = session['user']
            
            # セッション継続時間の計算
            if session['session_start'] and session['session_end']:
                duration = session['session_end'] - session['session_start']
                session['session_duration_seconds'] = int(duration.total_seconds())
            elif session['session_start']:
                # tunnel-downがない場合、最後のトラフィック時刻を使用
                if session['traffic_events']:
                    last_traffic = max(session['traffic_events'], 
                                     key=lambda x: x['timestamp'])
                    last_time = datetime.strptime(last_traffic['timestamp'], '%Y-%m-%d %H:%M:%S')
                    duration = last_time - session['session_start']
                    session['session_duration_seconds'] = int(duration.total_seconds())
                    session['session_status'] = 'active'  # まだアクティブ
            
            # ユーザーサマリーの更新
            summary = user_summary[user]
            summary['total_sessions'] += 1
            
            if session['session_status'] == 'active':
                summary['active_sessions'] += 1
            elif session['session_status'] == 'closed':
                summary['closed_sessions'] += 1
            
            summary['total_bytes_transfer'] += session['total_bytes_transfer']
            summary['unique_source_ips'].add(session['srcip'])
            summary['unique_assign_ips'].add(session['assignip'])
            summary['countries'].update(session['countries'])
            summary['total_session_duration'] += session['session_duration_seconds']
            
            if session['session_start']:
                if summary['first_connection'] is None or session['session_start'] < summary['first_connection']:
                    summary['first_connection'] = session['session_start']
                if summary['last_connection'] is None or session['session_start'] > summary['last_connection']:
                    summary['last_connection'] = session['session_start']

        logger.info(f"VPNセッション分析完了: {len(vpn_sessions)}セッション, {len(user_summary)}ユーザー")
        
        # setをlistに変換、dictを文字列に変換（CSV出力用）
        def convert_to_strings(items):
            """setやdictを含むリストを文字列リストに変換"""
            if not items:
                return []
            result = []
            for item in items:
                if isinstance(item, (str, int, float)):
                    result.append(str(item))
                elif isinstance(item, dict):
                    # dictの場合は主要な値を抽出
                    result.append(str(item.get('name', item.get('value', item.get('action', str(item))))))
                else:
                    result.append(str(item))
            return result

        for session_key, session in vpn_sessions.items():
            session['unique_destinations'] = convert_to_strings(list(session['unique_destinations']))
            session['countries'] = convert_to_strings(list(session['countries']))
            session['actions'] = convert_to_strings(list(session['actions']))
            session['services'] = convert_to_strings(list(session['services']))
            session['connection_reason'] = convert_to_strings(list(session['connection_reason']))
            
            # VPNイベントとトラフィックイベントをCSV出力用に変換
            vpn_events = session.get('vpn_events', [])
            if vpn_events:
                # 主要なVPNイベントアクションのみを文字列で記録
                vpn_actions = []
                for event in vpn_events:
                    if isinstance(event, dict):
                        vpn_actions.append(str(event.get('action', '')))
                    else:
                        vpn_actions.append(str(event))
                session['vpn_events_summary'] = ', '.join(filter(None, vpn_actions))
            else:
                session['vpn_events_summary'] = ''
            
            traffic_events = session.get('traffic_events', [])
            if traffic_events:
                # トラフィックイベントの概要を文字列で記録
                traffic_summary = []
                for event in traffic_events[:5]:  # 最初の5つまで
                    if isinstance(event, dict):
                        timestamp = str(event.get('timestamp', ''))
                        action = str(event.get('action', ''))
                        summary_str = f"{timestamp}:{action}" if timestamp and action else str(event)
                        traffic_summary.append(summary_str)
                    else:
                        traffic_summary.append(str(event))
                if len(traffic_events) > 5:
                    traffic_summary.append(f"... (+{len(traffic_events) - 5} more)")
                session['traffic_events_summary'] = ', '.join(filter(None, traffic_summary))
            else:
                session['traffic_events_summary'] = ''
        
        for user, summary in user_summary.items():
            summary['unique_source_ips'] = convert_to_strings(list(summary['unique_source_ips']))
            summary['unique_assign_ips'] = convert_to_strings(list(summary['unique_assign_ips']))
            summary['countries'] = convert_to_strings(list(summary['countries']))
        
        return {
            'sessions': dict(vpn_sessions),
            'user_summary': dict(user_summary)
        }
    
    def _find_session_by_similarity(self, vpn_sessions, user, srcip, assignip, current_time):
        """従来の類似度ベースのセッション検索（フォールバック用）"""
        best_match_score = 0
        best_session = None
        best_reason = ""
        
        for session_key, session in vpn_sessions.items():
            if session['user'] != user:
                continue
                
            match_score = 0
            session_srcip = session.get('srcip', '')
            session_assignip = session.get('assignip', '')
            
            # IP一致チェック
            if session_assignip and assignip and session_assignip == assignip:
                match_score += 80
                reason = f"assignip一致({assignip})"
            elif session_srcip and srcip and session_srcip == srcip:
                match_score += 70
                reason = f"srcip一致({srcip})"
            elif session_assignip and srcip and session_assignip == srcip:
                match_score += 60
                reason = f"assign-src一致({srcip})"
            else:
                match_score += 10
                reason = "ユーザー名のみ"
            
            # 時間チェック
            session_start = session.get('session_start')
            session_end = session.get('session_end')
            
            if session_start:
                if current_time >= session_start:
                    if session_end is None or current_time <= session_end:
                        match_score += 20
                        reason += "+時間内"
                    elif (current_time - session_end).total_seconds() <= 600:
                        match_score += 10
                        reason += "+時間猶予"
            
            if match_score > best_match_score:
                best_match_score = match_score
                best_session = session
                best_reason = reason
        
        # 最低閾値チェック
        if best_match_score >= 20:
            return best_session, best_reason
        else:
            return None, "閾値未満"

class TimelineAnalyzer:
    """タイムライン分析器（設定外部化対応）"""

    def __init__(self, config: ForensicConfig = None):
        self.config = config or ForensicConfig()

    def create_timeline(self, parsed_logs: List[Dict[str, str]], vpn_sessions: Dict = None) -> List[Dict]:
        """時系列タイムラインを作成（BI分析用拡張）"""
        timeline_events = []
        
        # VPNセッション情報のマッピング用
        session_lookup = {}
        if vpn_sessions:
            for session_key, session in vpn_sessions.items():
                user = session.get('user', '')
                assignip = session.get('assignip', '')
                if user and assignip:
                    session_lookup[(user, assignip)] = session

        for log in parsed_logs:
            if 'date' in log and 'time' in log:
                try:
                    # 日時情報を結合
                    datetime_str = f"{log['date']} {log['time']}"
                    dt = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
                    
                    # 基本情報
                    user = log.get('user', 'unknown')
                    srcip = log.get('srcip', 'unknown')
                    dstip = log.get('dstip', 'unknown')
                    dstport = log.get('dstport', 'unknown')
                    action = log.get('action', 'unknown')
                    sentbyte = int(log.get('sentbyte', 0))
                    rcvdbyte = int(log.get('rcvdbyte', 0))
                    service = log.get('service', 'unknown')
                    assignip = log.get('assignip', '')
                    protocol = log.get('proto', 'unknown')
                    
                    # === 最小限のBI分析用フィールド ===
                    
                    # 時間分析（基礎データのみ）
                    hour = dt.hour
                    weekday = dt.weekday()  # 0=Monday, 6=Sunday
                    
                    # セッション・コンテキスト
                    related_session = session_lookup.get((user, assignip)) or session_lookup.get((user, srcip))
                    
                    vpn_session_id = ''
                    session_status = 'unknown'
                    
                    if related_session:
                        # セッションキーを探す
                        for sk, sess in vpn_sessions.items():
                            if sess == related_session:
                                vpn_session_id = sk
                                break
                        session_status = related_session.get('session_status', 'unknown')

                    event = {
                        # 基本ログデータ
                        'timestamp': dt,
                        'datetime_str': datetime_str,
                        'user': user,
                        'srcip': srcip,
                        'dstip': dstip,
                        'dstport': dstport,
                        'action': action,
                        'sentbyte': sentbyte,
                        'rcvdbyte': rcvdbyte,
                        'service': service,
                        'assignip': assignip,
                        'protocol': protocol,
                        'srccountry': log.get('srccountry', ''),
                        'dstcountry': log.get('dstcountry', ''),
                        
                        # 最小限のBI分析フィールド
                        'hour': hour,
                        'day_of_week': weekday,
                        'vpn_session_id': vpn_session_id,
                        'session_status': session_status,
                        'source_country': log.get('srccountry', ''),
                        'destination_country': log.get('dstcountry', ''),
                        'data_direction': self._get_data_direction(srcip, dstip)
                    }
                    
                    timeline_events.append(event)
                except ValueError:
                    continue

        # タイムスタンプでソート
        timeline_events.sort(key=lambda x: x['timestamp'])

        logger.info(f"タイムライン作成: {len(timeline_events)}件のイベント")
        return timeline_events
    
    def _get_data_direction(self, srcip: str, dstip: str) -> str:
        """データ転送方向を判定（BI分析用事前計算）"""
        # 既存のIPAnalyzerを活用してより効率的に判定
        src_private = self.config and hasattr(self, 'ip_analyzer') and self.ip_analyzer.is_private_ip(srcip) if hasattr(self, 'ip_analyzer') else self._is_private_ip_simple(srcip)
        dst_private = self.config and hasattr(self, 'ip_analyzer') and self.ip_analyzer.is_private_ip(dstip) if hasattr(self, 'ip_analyzer') else self._is_private_ip_simple(dstip)
        
        if src_private and dst_private:
            return 'Internal'
        elif src_private and not dst_private:
            return 'Outbound'
        elif not src_private and dst_private:
            return 'Inbound'
        else:
            return 'External'
    
    def _is_private_ip_simple(self, ip: str) -> bool:
        """簡易プライベートIP判定（フォールバック用）"""
        if not ip or ip == 'unknown':
            return False
        try:
            octets = ip.split('.')
            if len(octets) == 4:
                first = int(octets[0])
                second = int(octets[1])
                if first == 10:
                    return True
                elif first == 172 and 16 <= second <= 31:
                    return True
                elif first == 192 and second == 168:
                    return True
        except:
            pass
        return False

    def analyze_time_patterns(self, timeline: List[Dict]) -> Dict:
        """時間パターンを分析"""
        hour_stats = defaultdict(int)
        day_stats = defaultdict(int)

        for event in timeline:
            hour = event['timestamp'].hour
            day = event['timestamp'].strftime("%Y-%m-%d")

            hour_stats[hour] += 1
            day_stats[day] += 1

        return {
            'hourly_distribution': dict(hour_stats),
            'daily_distribution': dict(day_stats),
            'peak_hour': max(hour_stats, key=hour_stats.get) if hour_stats else None,
            'peak_day': max(day_stats, key=day_stats.get) if day_stats else None
        }

class PortAnalyzer:
    """ポート分析器（2025年版・可読性改善対応）"""

    def __init__(self, config: ForensicConfig = None):
        self.config = config or ForensicConfig()
        
        # 設定から2025年版ポート分類を取得
        self.critical_ports = self.config.CRITICAL_PORTS.copy()
        self.admin_ports = self.config.ADMIN_PORTS.copy()
        self.standard_ports = self.config.STANDARD_PORTS.copy()
        
        logger.info(f"ポート分類読み込み完了:")
        logger.info(f"  - クリティカルポート: {len(self.critical_ports)}個")
        logger.info(f"  - 管理ポート: {len(self.admin_ports)}個") 
        logger.info(f"  - 標準ポート: {len(self.standard_ports)}個")

    def categorize_ports(self, port_connections: Dict) -> Dict:
        """ポートを重要度別に分類"""
        categorized = {
            'critical': {},
            'admin': {},
            'standard': {},
            'other': {}
        }

        for port_str, count in port_connections.items():
            try:
                port = int(port_str)
                if port in self.critical_ports:
                    categorized['critical'][port] = count
                elif port in self.admin_ports:
                    categorized['admin'][port] = count
                elif port in self.standard_ports:
                    categorized['standard'][port] = count
                else:
                    categorized['other'][port] = count
            except ValueError:
                categorized['other'][port_str] = count

        return categorized

    def format_port_display(self, categorized_ports: Dict, service_map: Dict = None) -> Dict:
        """ポート情報を可読性の高い形式でフォーマット"""
        if service_map is None:
            service_map = {**self.critical_ports, **self.admin_ports, **self.standard_ports}

        def format_port_list(port_dict, max_display=3):
            if not port_dict:
                return 'None'

            # 接続数でソート
            sorted_ports = sorted(port_dict.items(), key=lambda x: x[1], reverse=True)

            port_strs = []
            for port, count in sorted_ports[:max_display]:
                service_name = service_map.get(port, f'Port-{port}')
                port_strs.append(f"{port}({service_name}):{count}times")

            if len(sorted_ports) > max_display:
                remaining = len(sorted_ports) - max_display
                port_strs.append(f"+{remaining}others")

            return ', '.join(port_strs)

        # 上位5ポートを取得（全カテゴリから）
        all_ports = {}
        for category_ports in categorized_ports.values():
            all_ports.update(category_ports)

        top_5_ports = dict(sorted(all_ports.items(), key=lambda x: x[1], reverse=True)[:5])

        return {
            'critical_ports': format_port_list(categorized_ports['critical']),
            'admin_ports': format_port_list(categorized_ports['admin']),
            'top_5_ports': format_port_list(top_5_ports, 5),
            'other_ports_count': len(categorized_ports['other'])
        }

class LogAnalyzer:
    """メインログ分析器（設定外部化対応）"""

    def __init__(self, config: ForensicConfig = None):
        self.config = config or ForensicConfig()
        
        # 各分析器を設定付きで初期化
        self.parser = FortigateLogParser()
        self.ip_analyzer = IPAnalyzer(self.config)
        self.geo_analyzer = GeolocationAnalyzer(self.config)
        self.timeline_analyzer = TimelineAnalyzer(self.config)
        self.port_analyzer = PortAnalyzer(self.config)
        self.vpn_analyzer = VPNSessionAnalyzer(self.config)  # VPN分析器を追加
        
        logger.info("分析器初期化完了（2025年版設定適用・VPN分析器含む）")

    def analyze_destination_ips_and_subnets(self, parsed_logs: List[Dict[str, str]]) -> Tuple[Dict, Dict, Dict, Dict]:
        """宛先IP分析とサブネット分析を統合実行（パフォーマンス改善版）"""
        # IP統計用
        private_ip_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ports': set(),
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'is_high_risk': False,
            'port_connections': defaultdict(int),
            'countries': set()
        })

        global_ip_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ports': set(),
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'port_connections': defaultdict(int),
            'countries': set()
        })

        # サブネット統計用
        private_subnet_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ips': set(),
            'high_risk_ips': set(),
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'port_connections': defaultdict(int)
        })

        global_subnet_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ips': set(),
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'port_connections': defaultdict(int)
        })

        # 一度のループで両方の統計を計算
        for log in parsed_logs:
            dstip = log.get('dstip')
            if not dstip:
                continue

            # 基本統計値
            dstport = log.get('dstport')
            bytes_sent = int(log.get('sentbyte', 0))
            bytes_received = int(log.get('rcvdbyte', 0))
            country = log.get('dstcountry')

            # サブネット取得
            subnet = self.ip_analyzer.get_subnet(dstip)

            # プライベート/グローバル分離
            if self.ip_analyzer.is_private_ip(dstip):
                # プライベートIP統計
                ip_stats = private_ip_stats[dstip]
                ip_stats['connection_count'] += 1
                ip_stats['total_bytes_sent'] += bytes_sent
                ip_stats['total_bytes_received'] += bytes_received
                if dstport:
                    ip_stats['unique_ports'].add(dstport)
                    ip_stats['port_connections'][dstport] += 1
                ip_stats['is_high_risk'] = self.ip_analyzer.is_high_risk_ip(dstip)
                if country:
                    ip_stats['countries'].add(country)

                # プライベートサブネット統計
                subnet_stats = private_subnet_stats[subnet]
                subnet_stats['connection_count'] += 1
                subnet_stats['unique_ips'].add(dstip)
                subnet_stats['total_bytes_sent'] += bytes_sent
                subnet_stats['total_bytes_received'] += bytes_received
                if dstport:
                    subnet_stats['port_connections'][dstport] += 1
                if self.ip_analyzer.is_high_risk_ip(dstip):
                    subnet_stats['high_risk_ips'].add(dstip)
            else:
                # グローバルIP統計
                ip_stats = global_ip_stats[dstip]
                ip_stats['connection_count'] += 1
                ip_stats['total_bytes_sent'] += bytes_sent
                ip_stats['total_bytes_received'] += bytes_received
                if dstport:
                    ip_stats['unique_ports'].add(dstport)
                    ip_stats['port_connections'][dstport] += 1
                if country:
                    ip_stats['countries'].add(country)

                # グローバルサブネット統計
                subnet_stats = global_subnet_stats[subnet]
                subnet_stats['connection_count'] += 1
                subnet_stats['unique_ips'].add(dstip)
                subnet_stats['total_bytes_sent'] += bytes_sent
                subnet_stats['total_bytes_received'] += bytes_received
                if dstport:
                    subnet_stats['port_connections'][dstport] += 1

        # setをlistに変換し、defaultdictをdictに変換
        def convert_stats(stats_dict):
            result = {}
            for key, stats in stats_dict.items():
                converted_stats = dict(stats)
                converted_stats['unique_ports'] = list(converted_stats.get('unique_ports', []))
                converted_stats['port_connections'] = dict(converted_stats.get('port_connections', {}))
                converted_stats['countries'] = list(converted_stats.get('countries', []))
                if 'unique_ips' in converted_stats:
                    converted_stats['unique_ips'] = list(converted_stats['unique_ips'])
                if 'high_risk_ips' in converted_stats:
                    converted_stats['high_risk_ips'] = list(converted_stats['high_risk_ips'])
                result[key] = converted_stats
            return result

        return (convert_stats(private_ip_stats), convert_stats(global_ip_stats),
                convert_stats(private_subnet_stats), convert_stats(global_subnet_stats))

    def analyze_destination_ips(self, parsed_logs: List[Dict[str, str]]) -> Tuple[Dict, Dict]:
        """宛先IP分析（プライベート/グローバル分離）"""
        private_ip_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ports': set(),
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'is_high_risk': False,
            'port_connections': defaultdict(int),
            'countries': set()
        })

        global_ip_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ports': set(),
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'port_connections': defaultdict(int),
            'countries': set()
        })

        for log in parsed_logs:
            dstip = log.get('dstip')
            if not dstip:
                continue

            # 基本統計
            stats_update = {
                'connection_count': 1,
                'total_bytes_sent': int(log.get('sentbyte', 0)),
                'total_bytes_received': int(log.get('rcvdbyte', 0))
            }

            # ポート情報
            dstport = log.get('dstport')
            if dstport:
                stats_update['unique_ports'] = {dstport}
                stats_update['port_connections'] = {dstport: 1}

            # 国情報
            if log.get('dstcountry'):
                stats_update['countries'] = {log.get('dstcountry')}

            # プライベート/グローバル分離
            if self.ip_analyzer.is_private_ip(dstip):
                # プライベートIP
                stats = private_ip_stats[dstip]
                stats['connection_count'] += stats_update['connection_count']
                stats['total_bytes_sent'] += stats_update['total_bytes_sent']
                stats['total_bytes_received'] += stats_update['total_bytes_received']
                if dstport:
                    stats['unique_ports'].add(dstport)
                    stats['port_connections'][dstport] += 1
                stats['is_high_risk'] = self.ip_analyzer.is_high_risk_ip(dstip)
                if log.get('dstcountry'):
                    stats['countries'].add(log.get('dstcountry'))
            else:
                # グローバルIP
                stats = global_ip_stats[dstip]
                stats['connection_count'] += stats_update['connection_count']
                stats['total_bytes_sent'] += stats_update['total_bytes_sent']
                stats['total_bytes_received'] += stats_update['total_bytes_received']
                if dstport:
                    stats['unique_ports'].add(dstport)
                    stats['port_connections'][dstport] += 1
                if log.get('dstcountry'):
                    stats['countries'].add(log.get('dstcountry'))

        # setをlistに変換し、辞書をdictに変換
        def convert_sets_and_defaultdicts(stats_dict):
            result = {}
            for ip, stats in stats_dict.items():
                converted_stats = dict(stats)
                converted_stats['unique_ports'] = list(converted_stats['unique_ports'])
                converted_stats['port_connections'] = dict(converted_stats['port_connections'])
                converted_stats['countries'] = list(converted_stats['countries'])
                result[ip] = converted_stats
            return result

        return convert_sets_and_defaultdicts(private_ip_stats), convert_sets_and_defaultdicts(global_ip_stats)

    def analyze_subnets(self, parsed_logs: List[Dict[str, str]]) -> Tuple[Dict, Dict]:
        """サブネット分析（プライベート/グローバル分離）"""
        private_subnet_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ips': set(),
            'high_risk_ips': set(),
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'port_connections': defaultdict(int)
        })

        global_subnet_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ips': set(),
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'port_connections': defaultdict(int)
        })

        for log in parsed_logs:
            dstip = log.get('dstip')
            if not dstip:
                continue

            subnet = self.ip_analyzer.get_subnet(dstip)
            dstport = log.get('dstport')

            # 基本統計
            connection_count = 1
            bytes_sent = int(log.get('sentbyte', 0))
            bytes_received = int(log.get('rcvdbyte', 0))

            # プライベート/グローバル分離
            if self.ip_analyzer.is_private_ip(dstip):
                # プライベートサブネット
                stats = private_subnet_stats[subnet]
                stats['connection_count'] += connection_count
                stats['unique_ips'].add(dstip)
                stats['total_bytes_sent'] += bytes_sent
                stats['total_bytes_received'] += bytes_received
                if dstport:
                    stats['port_connections'][dstport] += 1

                # 高リスクIP判定
                if self.ip_analyzer.is_high_risk_ip(dstip):
                    stats['high_risk_ips'].add(dstip)
            else:
                # グローバルサブネット
                stats = global_subnet_stats[subnet]
                stats['connection_count'] += connection_count
                stats['unique_ips'].add(dstip)
                stats['total_bytes_sent'] += bytes_sent
                stats['total_bytes_received'] += bytes_received
                if dstport:
                    stats['port_connections'][dstport] += 1

        # setをlistに変換し、defaultdictをdictに変換
        def convert_sets_and_defaultdicts(stats_dict):
            result = {}
            for subnet, stats in stats_dict.items():
                converted_stats = dict(stats)
                converted_stats['unique_ips'] = list(converted_stats['unique_ips'])
                converted_stats['port_connections'] = dict(converted_stats['port_connections'])
                if 'high_risk_ips' in converted_stats:
                    converted_stats['high_risk_ips'] = list(converted_stats['high_risk_ips'])
                result[subnet] = converted_stats
            return result

        return convert_sets_and_defaultdicts(private_subnet_stats), convert_sets_and_defaultdicts(global_subnet_stats)

    def analyze_ports(self, parsed_logs: List[Dict[str, str]]) -> Dict:
        """ポート分析"""
        port_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ips': set(),
            'total_bytes': 0,
            'service_name': 'unknown'
        })

        # サービス名マッピング
        service_map = {**self.port_analyzer.critical_ports, 
                      **self.port_analyzer.admin_ports, 
                      **self.port_analyzer.standard_ports}

        for log in parsed_logs:
            dstport = log.get('dstport')
            if not dstport:
                continue

            try:
                port_num = int(dstport)
                stats = port_stats[dstport]
                stats['connection_count'] += 1
                stats['total_bytes'] += int(log.get('sentbyte', 0)) + int(log.get('rcvdbyte', 0))
                stats['service_name'] = service_map.get(port_num, f'Port-{port_num}')

                dstip = log.get('dstip')
                if dstip:
                    stats['unique_ips'].add(dstip)
            except ValueError:
                continue

        # setをlistに変換
        result = {}
        for port, stats in port_stats.items():
            converted_stats = dict(stats)
            converted_stats['unique_ips'] = list(converted_stats['unique_ips'])
            converted_stats['unique_ip_count'] = len(converted_stats['unique_ips'])
            result[port] = converted_stats

        return result

    def analyze_data_transfer(self, parsed_logs: List[Dict[str, str]]) -> Dict:
        """データ転送量分析"""
        transfer_stats = defaultdict(lambda: {
            'total_sent': 0,
            'total_received': 0,
            'total_transfer': 0,
            'session_count': 0,
            'avg_session_size': 0
        })

        for log in parsed_logs:
            dstip = log.get('dstip', 'unknown')
            sent_bytes = int(log.get('sentbyte', 0))
            rcvd_bytes = int(log.get('rcvdbyte', 0))

            stats = transfer_stats[dstip]
            stats['total_sent'] += sent_bytes
            stats['total_received'] += rcvd_bytes
            stats['total_transfer'] += sent_bytes + rcvd_bytes
            stats['session_count'] += 1

        # 平均セッションサイズを計算
        for dstip, stats in transfer_stats.items():
            if stats['session_count'] > 0:
                stats['avg_session_size'] = stats['total_transfer'] / stats['session_count']

        return dict(transfer_stats)

class ReportGenerator:
    """レポート生成器（エラー修正版）"""

    def __init__(self, output_dir: str = "./forensic_output", config: ForensicConfig = None):
        self.config = config or ForensicConfig()
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        # PortAnalyzerのインスタンスを設定付きで作成
        self.port_analyzer = PortAnalyzer(self.config)

        # サービス名マッピング（2025年版）
        self.service_map = {
            **self.port_analyzer.critical_ports,
            **self.port_analyzer.admin_ports,
            **self.port_analyzer.standard_ports
        }
        
        logger.info(f"レポート生成器初期化完了（総サービス数: {len(self.service_map)}）")

    def _validate_report_data(self, data: Any, report_type: str) -> bool:
        """レポートデータの妥当性を検証"""
        try:
            if data is None:
                logger.warning(f"データが空です ({report_type})")
                return False

            if report_type in ['subnet_private', 'subnet_global', 'destination_ip_private', 'destination_ip_global']:
                if not isinstance(data, dict):
                    logger.error(f"辞書型が期待されますが{type(data)}が渡されました ({report_type})")
                    return False
                
                if not data:
                    logger.warning(f"空の辞書です ({report_type})")
                    return True  # 空でも有効

                # サンプルデータの検証
                sample_key = next(iter(data))
                sample_data = data[sample_key]
                if not isinstance(sample_data, dict):
                    logger.error(f"データ要素が辞書型ではありません ({report_type}): {type(sample_data)}")
                    return False

            elif report_type == 'timeline':
                if not isinstance(data, list):
                    logger.error(f"リスト型が期待されますが{type(data)}が渡されました ({report_type})")
                    return False

            elif report_type in ['port_analysis', 'data_transfer', 'geolocation']:
                if not isinstance(data, dict):
                    logger.error(f"辞書型が期待されますが{type(data)}が渡されました ({report_type})")
                    return False

            elif report_type in ['vpn_sessions', 'vpn_user_summary']:
                if not isinstance(data, dict):
                    logger.error(f"辞書型が期待されますが{type(data)}が渡されました ({report_type})")
                    return False
                
                # VPNデータの構造確認
                if report_type == 'vpn_sessions' and 'sessions' not in data:
                    logger.error(f"VPNセッションデータに'sessions'キーがありません")
                    return False
                elif report_type == 'vpn_user_summary' and 'user_summary' not in data:
                    logger.error(f"VPNユーザーサマリーデータに'user_summary'キーがありません")
                    return False

            return True

        except Exception as e:
            logger.error(f"データ検証中にエラー ({report_type}): {e}")
            return False

    def _suggest_alternative_path(self, original_path: str) -> str:
        """代替パスを提案"""
        try:
            # ユーザーのホームディレクトリを試す
            home_dir = os.path.expanduser("~")
            alt_dir = os.path.join(home_dir, "forensic_output_alt")
            alt_path = original_path.replace(self.output_dir, alt_dir)
            
            logger.info(f"代替パスを提案: {alt_path}")
            return alt_path
        except Exception:
            # 最終手段として一時ディレクトリ
            import tempfile
            temp_dir = tempfile.gettempdir()
            alt_path = os.path.join(temp_dir, "forensic_output", os.path.basename(original_path))
            logger.info(f"一時ディレクトリを使用: {alt_path}")
            return alt_path

    def _generate_error_report(self, data: Any, filename: str, error_message: str):
        """エラー情報を含むレポートを生成"""
        try:
            error_filename = filename.replace('.csv', '_error.txt')
            os.makedirs(os.path.dirname(error_filename), exist_ok=True)
            
            with open(error_filename, 'w', encoding='utf-8') as f:
                f.write(f"エラーレポート\n")
                f.write(f"生成日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"対象ファイル: {filename}\n")
                f.write(f"エラー内容: {error_message}\n")
                f.write(f"データ型: {type(data)}\n")
                f.write(f"データサンプル: {str(data)[:500]}...\n")
            
            logger.info(f"エラーレポート生成: {error_filename}")
        except Exception as e:
            logger.error(f"エラーレポート生成失敗: {e}")

    def generate_csv_report(self, data: Any, filename: str, report_type: str = 'general'):
        """CSV形式でレポート生成（エラーハンドリング強化版）"""
        original_filename = filename
        
        try:
            # ディレクトリ作成
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            # データ検証
            if not self._validate_report_data(data, report_type):
                raise ValueError(f"Invalid data for report type: {report_type}")
            
            # 具体的なCSV生成処理
            if report_type == 'subnet_private':
                self._generate_subnet_private_csv(data, filename)
            elif report_type == 'subnet_global':
                self._generate_subnet_global_csv(data, filename)
            elif report_type == 'destination_ip_private':
                self._generate_ip_private_csv(data, filename)
            elif report_type == 'destination_ip_global':
                self._generate_ip_global_csv(data, filename)
            elif report_type == 'port_analysis':
                self._generate_port_csv(data, filename)
            elif report_type == 'timeline':
                self._generate_timeline_csv(data, filename)
            elif report_type == 'data_transfer':
                self._generate_transfer_csv(data, filename)
            elif report_type == 'geolocation':
                self._generate_geolocation_csv(data, filename)
            elif report_type == 'vpn_sessions':
                self._generate_vpn_sessions_csv(data, filename)
            elif report_type == 'vpn_user_summary':
                self._generate_vpn_user_summary_csv(data, filename)
            else:
                self._generate_general_csv(data, filename)
            
            logger.info(f"CSV生成成功: {filename}")

        except PermissionError as e:
            logger.error(f"権限エラー: {filename} への書き込み権限がありません")
            # 代替パスで再試行
            alt_filename = self._suggest_alternative_path(filename)
            try:
                os.makedirs(os.path.dirname(alt_filename), exist_ok=True)
                self.generate_csv_report(data, alt_filename, report_type)
            except Exception as retry_error:
                logger.error(f"代替パスでも失敗: {retry_error}")
                self._generate_error_report(data, original_filename, f"権限エラー: {e}")

        except OSError as e:
            if e.errno == errno.ENOSPC:  # No space left on device
                logger.error(f"ディスク容量不足: {filename}")
                self._generate_error_report(data, original_filename, f"ディスク容量不足: {e}")
            elif e.errno == errno.ENAMETOOLONG:  # File name too long
                logger.error(f"ファイル名が長すぎます: {filename}")
                # 短いファイル名で再試行
                short_filename = filename[:200] + ".csv"
                try:
                    self.generate_csv_report(data, short_filename, report_type)
                except Exception:
                    self._generate_error_report(data, original_filename, f"ファイル名エラー: {e}")
            else:
                logger.error(f"ファイルI/Oエラー: {e}")
                self._generate_error_report(data, original_filename, f"I/Oエラー: {e}")

        except ValueError as e:
            logger.error(f"データ形式エラー ({report_type}): {e}")
            # フォールバック処理で汎用CSV生成
            try:
                fallback_filename = filename.replace('.csv', '_fallback.csv')
                self._generate_general_csv(data, fallback_filename)
                logger.info(f"フォールバックCSV生成: {fallback_filename}")
            except Exception as fallback_error:
                logger.error(f"フォールバック処理も失敗: {fallback_error}")
                self._generate_error_report(data, original_filename, f"データエラー: {e}")

        except KeyError as e:
            logger.error(f"データ構造エラー ({report_type}): 必須キー不足 {e}")
            self._generate_error_report(data, original_filename, f"データ構造エラー: {e}")

        except UnicodeEncodeError as e:
            logger.error(f"文字エンコードエラー ({report_type}): {e}")
            # UTF-8以外のエンコーディングで再試行
            try:
                alt_filename = filename.replace('.csv', '_alt_encoding.csv')
                # エンコーディングを変更して再生成
                self._generate_csv_with_alt_encoding(data, alt_filename, report_type)
            except Exception:
                self._generate_error_report(data, original_filename, f"エンコードエラー: {e}")

        except Exception as e:
            logger.error(f"予期しないエラー ({report_type}): {e}")
            logger.debug(f"詳細なトレースバック:\n{traceback.format_exc()}")
            self._generate_error_report(data, original_filename, f"予期しないエラー: {e}")

    def _generate_csv_with_alt_encoding(self, data: Any, filename: str, report_type: str):
        """代替エンコーディングでCSV生成"""
        # 実装は元のメソッドと同じだが、エンコーディングを変更
        # 簡略化のため、エラー時の文字を置換
        try:
            if report_type == 'general':
                self._generate_general_csv_safe(data, filename)
            else:
                # 他のメソッドも同様に安全な文字列変換を使用
                self._generate_general_csv_safe(data, filename)
        except Exception as e:
            logger.error(f"代替エンコーディングでも失敗: {e}")
            raise

    def _generate_general_csv_safe(self, data: Any, filename: str):
        """安全な汎用CSV生成（文字エラー対応）"""
        fieldnames = ['key', 'value']

        with open(filename, 'w', newline='', encoding='utf-8', errors='replace') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            try:
                if isinstance(data, dict):
                    for key, value in data.items():
                        safe_key = str(key).encode('utf-8', errors='replace').decode('utf-8')
                        safe_value = str(value).encode('utf-8', errors='replace').decode('utf-8')
                        writer.writerow({'key': safe_key, 'value': safe_value})
                elif isinstance(data, list):
                    for i, item in enumerate(data):
                        safe_item = str(item).encode('utf-8', errors='replace').decode('utf-8')
                        writer.writerow({'key': f'item_{i}', 'value': safe_item})
                else:
                    safe_data = str(data).encode('utf-8', errors='replace').decode('utf-8')
                    writer.writerow({'key': 'data', 'value': safe_data})
            except Exception as e:
                # 最後の手段
                writer.writerow({'key': 'error', 'value': f'データ処理エラー: {str(e)}'})

        logger.info(f"安全なCSV生成完了: {filename}")

    def _generate_subnet_private_csv(self, subnet_stats: Dict, filename: str):
        """Private subnet analysis CSV (sorted by total_bytes, unique_ports top 10+other, English output)"""
        fieldnames = ['subnet', 'ip_type', 'connection_count', 'unique_ip_count', 'high_risk_ip_count',
                     'total_bytes', 'unique_ports']

        try:
            # total_bytesで降順ソート
            def total_bytes(stats):
                return stats.get('total_bytes_sent', 0) + stats.get('total_bytes_received', 0)
            sorted_items = sorted(subnet_stats.items(), key=lambda x: total_bytes(x[1]), reverse=True)

            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for subnet, stats in sorted_items:
                    try:
                        if not isinstance(stats, dict):
                            logger.warning(f"Invalid stats type (subnet: {subnet}): {type(stats)}")
                            continue

                        unique_ips = stats.get('unique_ips', [])
                        high_risk_ips = stats.get('high_risk_ips', [])
                        if not isinstance(unique_ips, list):
                            unique_ips = []
                        if not isinstance(high_risk_ips, list):
                            high_risk_ips = []

                        # unique_ports: 利用回数順で上位10件（443(1000)形式）、その他はother(N)で集約
                        port_connections = stats.get('port_connections', {})
                        sorted_ports = sorted(port_connections.items(), key=lambda x: x[1], reverse=True)
                        unique_ports_list = [f"{port}({count})" for port, count in sorted_ports[:10]]
                        if len(sorted_ports) > 10:
                            other_count = sum(count for _, count in sorted_ports[10:])
                            unique_ports_list.append(f"other({other_count})")
                        unique_ports_str = ', '.join(unique_ports_list) if unique_ports_list else 'None'

                        total_bytes_val = stats.get('total_bytes_sent', 0) + stats.get('total_bytes_received', 0)

                        row = {
                            'subnet': str(subnet),
                            'ip_type': 'Private',
                            'connection_count': int(stats.get('connection_count', 0)),
                            'unique_ip_count': len(unique_ips),
                            'high_risk_ip_count': len(high_risk_ips),
                            'total_bytes': f"{total_bytes_val:,}",
                            'unique_ports': unique_ports_str
                        }
                        writer.writerow(row)

                    except Exception as row_error:
                        logger.error(f"Row error (subnet: {subnet}): {row_error}")
                        error_row = {
                            'subnet': str(subnet),
                            'ip_type': 'Private',
                            'connection_count': 'Error',
                            'unique_ip_count': 'Error',
                            'high_risk_ip_count': 'Error',
                            'total_bytes': 'Error',
                            'unique_ports': 'Error'
                        }
                        writer.writerow(error_row)
                        continue

        except Exception as file_error:
            logger.error(f"File write error ({filename}): {file_error}")
            raise

    def _generate_subnet_global_csv(self, subnet_stats: Dict, filename: str):
        """Global subnet analysis CSV (sorted by total_bytes, unique_ports top 10+other, English output)"""
        fieldnames = ['subnet', 'ip_type', 'connection_count', 'unique_ip_count',
                     'total_bytes', 'unique_ports']

        try:
            def total_bytes(stats):
                return stats.get('total_bytes_sent', 0) + stats.get('total_bytes_received', 0)
            sorted_items = sorted(subnet_stats.items(), key=lambda x: total_bytes(x[1]), reverse=True)

            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for subnet, stats in sorted_items:
                    try:
                        if not isinstance(stats, dict):
                            logger.warning(f"Invalid stats type for subnet {subnet}: {type(stats)}")
                            continue

                        unique_ips = stats.get('unique_ips', [])
                        if not isinstance(unique_ips, list):
                            unique_ips = []

                        port_connections = stats.get('port_connections', {})
                        sorted_ports = sorted(port_connections.items(), key=lambda x: x[1], reverse=True)
                        unique_ports_list = [f"{port}({count})" for port, count in sorted_ports[:10]]
                        if len(sorted_ports) > 10:
                            other_count = sum(count for _, count in sorted_ports[10:])
                            unique_ports_list.append(f"other({other_count})")
                        unique_ports_str = ', '.join(unique_ports_list) if unique_ports_list else 'None'

                        total_bytes_val = stats.get('total_bytes_sent', 0) + stats.get('total_bytes_received', 0)

                        row = {
                            'subnet': subnet,
                            'ip_type': 'Global',
                            'connection_count': stats.get('connection_count', 0),
                            'unique_ip_count': len(unique_ips),
                            'total_bytes': f"{total_bytes_val:,}",
                            'unique_ports': unique_ports_str
                        }
                        writer.writerow(row)

                    except Exception as row_error:
                        logger.error(f"Row error (subnet: {subnet}): {row_error}")
                        error_row = {
                            'subnet': subnet,
                            'ip_type': 'Global',
                            'connection_count': 'Error',
                            'unique_ip_count': 'Error',
                            'total_bytes': 'Error',
                            'unique_ports': 'Error'
                        }
                        writer.writerow(error_row)
                        continue

        except Exception as file_error:
            logger.error(f"File write error ({filename}): {file_error}")
            raise

    def _generate_ip_private_csv(self, ip_stats: Dict, filename: str):
        """Private IP analysis CSV (sorted by total_bytes, unique_ports/port_details top 10, English output)"""
        fieldnames = ['destination_ip', 'ip_type', 'connection_count', 'unique_ports', 'total_bytes',
                     'is_high_risk', 'countries', 'port_details']

        def total_bytes(stats):
            return stats.get('total_bytes_sent', 0) + stats.get('total_bytes_received', 0)

        sorted_items = sorted(ip_stats.items(), key=lambda x: total_bytes(x[1]), reverse=True)

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for ip, stats in sorted_items:
                if not isinstance(stats, dict):
                    continue

                port_connections = stats.get('port_connections', {})
                # unique_ports: 利用回数順で上位10件（443(1000)形式）、その他はother(N)で集約
                sorted_ports = sorted(port_connections.items(), key=lambda x: x[1], reverse=True)
                unique_ports_list = [f"{port}({count})" for port, count in sorted_ports[:10]]
                if len(sorted_ports) > 10:
                    other_count = sum(count for _, count in sorted_ports[10:])
                    unique_ports_list.append(f"other({other_count})")
                unique_ports_str = ', '.join(unique_ports_list) if unique_ports_list else 'None'

                # port_details: 上位10件のみ表示
                port_details = []
                for port, count in sorted_ports[:10]:
                    try:
                        service_name = self.service_map.get(int(port), f'Port-{port}')
                    except Exception:
                        service_name = f'Port-{port}'
                    port_details.append(f"{port}({service_name}):{count} times")
                if len(sorted_ports) > 10:
                    port_details.append(f"+{len(sorted_ports)-10} more")

                row = {
                    'destination_ip': ip,
                    'ip_type': 'Private',
                    'connection_count': stats.get('connection_count', 0),
                    'unique_ports': unique_ports_str,
                    'total_bytes': f"{total_bytes(stats):,}",
                    'is_high_risk': 'High-Risk' if stats.get('is_high_risk', False) else 'Normal',
                    'countries': ', '.join(stats.get('countries', [])),
                    'port_details': ', '.join(port_details) if port_details else 'None'
                }
                writer.writerow(row)

    def _generate_ip_global_csv(self, ip_stats: Dict, filename: str):
        """Global IP analysis CSV (sorted by total_bytes, unique_ports/port_details top 10, English output)"""
        fieldnames = ['destination_ip', 'ip_type', 'connection_count', 'unique_ports', 'total_bytes',
                     'countries', 'port_details']

        def total_bytes(stats):
            return stats.get('total_bytes_sent', 0) + stats.get('total_bytes_received', 0)

        sorted_items = sorted(ip_stats.items(), key=lambda x: total_bytes(x[1]), reverse=True)

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for ip, stats in sorted_items:
                if not isinstance(stats, dict):
                    continue

                port_connections = stats.get('port_connections', {})
                # unique_ports: 利用回数順で上位10件（443(1000)形式）、その他はother(N)で集約
                sorted_ports = sorted(port_connections.items(), key=lambda x: x[1], reverse=True)
                unique_ports_list = [f"{port}({count})" for port, count in sorted_ports[:10]]
                if len(sorted_ports) > 10:
                    other_count = sum(count for _, count in sorted_ports[10:])
                    unique_ports_list.append(f"other({other_count})")
                unique_ports_str = ', '.join(unique_ports_list) if unique_ports_list else 'None'

                # port_details: 上位10件のみ表示
                port_details = []
                for port, count in sorted_ports[:10]:
                    try:
                        service_name = self.service_map.get(int(port), f'Port-{port}')
                    except Exception:
                        service_name = f'Port-{port}'
                    port_details.append(f"{port}({service_name}):{count} times")
                if len(sorted_ports) > 10:
                    port_details.append(f"+{len(sorted_ports)-10} more")

                row = {
                    'destination_ip': ip,
                    'ip_type': 'Global',
                    'connection_count': stats.get('connection_count', 0),
                    'unique_ports': unique_ports_str,
                    'total_bytes': f"{total_bytes(stats):,}",
                    'countries': ', '.join(stats.get('countries', [])),
                    'port_details': ', '.join(port_details) if port_details else 'None'
                }
                writer.writerow(row)

    def _generate_port_csv(self, port_stats: Dict, filename: str):
        """ポート分析CSV生成"""
        fieldnames = ['port', 'service_name', 'connection_count', 'unique_ip_count', 'total_bytes']

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for port, stats in sorted(port_stats.items(), key=lambda x: x[1]['connection_count'], reverse=True):
                if not isinstance(stats, dict):
                    continue

                row = {
                    'port': port,
                    'service_name': stats.get('service_name', 'unknown'),
                    'connection_count': stats.get('connection_count', 0),
                    'unique_ip_count': stats.get('unique_ip_count', 0),
                    'total_bytes': f"{stats.get('total_bytes', 0):,}"
                }
                writer.writerow(row)

    def _generate_timeline_csv(self, timeline: List[Dict], filename: str):
        """タイムライン分析CSV生成（timestamp昇順ソート＝時系列順）"""
        fieldnames = [
            'timestamp', 'user', 'srcip', 'dstip', 'dstport', 'action', 
            'bytes_sent', 'bytes_received', 'service', 'assignip', 'protocol',
            'hour', 'day_of_week',
            'vpn_session_id', 'session_status',
            'source_country', 'destination_country',
            'data_direction'
        ]

        # timestampで昇順ソート
        def get_timestamp(event):
            ts = event.get('timestamp')
            if isinstance(ts, str):
                try:
                    # 文字列ならdatetimeに変換
                    from datetime import datetime
                    return datetime.fromisoformat(ts)
                except Exception:
                    return ts
            return ts

        sorted_timeline = sorted(timeline, key=get_timestamp)

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for event in sorted_timeline:
                if not isinstance(event, dict):
                    continue

                row = {field: event.get(field, '') for field in fieldnames}
                for field in ['bytes_sent', 'bytes_received', 'hour', 'day_of_week']:
                    if field in row:
                        try:
                            if field == 'bytes_sent':
                                row[field] = int(event.get('sentbyte', 0))
                            elif field == 'bytes_received':
                                row[field] = int(event.get('rcvdbyte', 0))
                            else:
                                row[field] = int(row[field]) if row[field] else 0
                        except (ValueError, TypeError):
                            row[field] = 0
                writer.writerow(row)

    def _generate_transfer_csv(self, transfer_stats: Dict, filename: str):
        """データ転送量CSV生成"""
        fieldnames = ['destination_ip', 'total_sent_bytes', 'total_received_bytes', 
                     'total_transfer_bytes', 'session_count', 'avg_session_size']

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for ip, stats in sorted(transfer_stats.items(), key=lambda x: x[1]['total_transfer'], reverse=True):
                if not isinstance(stats, dict):
                    continue

                row = {
                    'destination_ip': ip,
                    'total_sent_bytes': f"{stats.get('total_sent', 0):,}",
                    'total_received_bytes': f"{stats.get('total_received', 0):,}",
                    'total_transfer_bytes': f"{stats.get('total_transfer', 0):,}",
                    'session_count': stats.get('session_count', 0),
                    'avg_session_size': f"{stats.get('avg_session_size', 0):,.1f}"
                }
                writer.writerow(row)

    def _generate_geolocation_csv(self, geo_stats: Dict, filename: str):
        """ジオロケーション分析CSV生成"""
        fieldnames = ['country', 'connection_count', 'unique_ip_count', 'total_bytes']

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for country, stats in sorted(geo_stats.items(), key=lambda x: x[1]['connection_count'], reverse=True):
                if not isinstance(stats, dict):
                    continue

                row = {
                    'country': country,
                    'connection_count': stats.get('connection_count', 0),
                    'unique_ip_count': stats.get('unique_ip_count', 0),
                    'total_bytes': f"{stats.get('total_bytes_sent', 0) + stats.get('total_bytes_received', 0):,}"
                }
                writer.writerow(row)

    def _generate_vpn_sessions_csv(self, vpn_data: Dict, filename: str):
        """VPNセッション詳細CSV生成"""
        sessions = vpn_data.get('sessions', {})

        fieldnames = [
            'session_key', 'user', 'source_ip', 'assigned_ip', 'tunnel_id',
            'session_start', 'session_end', 'session_duration', 'session_status',
            'total_bytes_transfer', 'bytes_sent', 'bytes_received', 'connection_count',
            'unique_destinations_count', 'destination_ips', 'countries', 
            'tunnel_info', 'tunnel_type', 'user_group', 'policy_id', 
            'actions', 'services', 'vpn_events_count', 'traffic_events_count', 
            'vpn_events_summary', 'traffic_events_summary', 'connection_reason',
            'inferred_reason'  # 推測セッションの理由
        ]

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for session_key, session in sessions.items():
                    if not isinstance(session, dict):
                        continue

                    try:
                        # セッション継続時間を時:分:秒形式に変換
                        duration_seconds = session.get('session_duration_seconds', 0)
                        duration_str = seconds_to_duration_str(duration_seconds)

                        # 日時のフォーマット
                        session_start = session.get('session_start')
                        session_end = session.get('session_end')
                        start_str = session_start.strftime('%Y-%m-%d %H:%M:%S') if session_start else ''
                        end_str = session_end.strftime('%Y-%m-%d %H:%M:%S') if session_end else ''

                        # 安全な文字列変換関数
                        def safe_join(items, separator=', '):
                            """リスト内の要素を安全に文字列結合"""
                            if not items:
                                return ''
                            string_items = []
                            for item in items:
                                if isinstance(item, (str, int, float)):
                                    string_items.append(str(item))
                                elif isinstance(item, dict):
                                    # dictの場合は主要な値を使用
                                    string_items.append(str(item.get('name', item.get('value', str(item)))))
                                else:
                                    string_items.append(str(item))
                            return separator.join(string_items)

                        # 宛先IPを制限（上位10個まで表示）
                        destinations = session.get('unique_destinations', [])
                        # destinationsが確実にリストであることを保証
                        if isinstance(destinations, set):
                            destinations = list(destinations)
                        elif not isinstance(destinations, list):
                            destinations = [str(destinations)] if destinations else []
                        
                        dest_display = safe_join(destinations[:10])
                        if len(destinations) > 10:
                            dest_display += f' (+{len(destinations) - 10} more)'

                        row = {
                            'session_key': session_key,
                            'user': session.get('user', ''),
                            'source_ip': session.get('srcip', ''),
                            'assigned_ip': session.get('assignip', ''),
                            'tunnel_id': session.get('tunnel_id', ''),
                            'session_start': start_str,
                            'session_end': end_str,
                            'session_duration': duration_str,
                            'session_status': session.get('session_status', 'unknown'),
                            'total_bytes_transfer': f"{session.get('total_bytes_transfer', 0):,}",
                            'bytes_sent': f"{session.get('total_bytes_sent', 0):,}",
                            'bytes_received': f"{session.get('total_bytes_received', 0):,}",
                            'connection_count': session.get('connection_count', 0),
                            'unique_destinations_count': len(destinations),
                            'destination_ips': dest_display,
                            'countries': safe_join(session.get('countries', [])),
                            'tunnel_info': session.get('tunnel_info', ''),
                            'tunnel_type': session.get('tunnel_type', ''),
                            'user_group': session.get('user_group', ''),
                            'policy_id': session.get('policy_id', ''),
                            'actions': safe_join(session.get('actions', [])),
                            'services': safe_join(session.get('services', [])),
                            'vpn_events_count': len(session.get('vpn_events', [])),
                            'traffic_events_count': len(session.get('traffic_events', [])),
                            'vpn_events_summary': session.get('vpn_events_summary', ''),
                            'traffic_events_summary': session.get('traffic_events_summary', ''),
                            'connection_reason': safe_join(session.get('connection_reason', [])),
                            'inferred_reason': session.get('inferred_reason', '')  # 推測セッションの理由
                        }
                        
                        # ゼロ接続セッションの調査用ログ
                        if session_key == 'fom_tunnel_1204628915':
                            logger.warning(f"[CSV出力調査] fom_tunnel_1204628915の情報: "
                                         f"assignip:'{session.get('assignip', '')}', "
                                         f"srcip:'{session.get('srcip', '')}', "
                                         f"connection_count:{session.get('connection_count', 0)}")
                        
                        writer.writerow(row)
                        
                    except Exception as row_error:
                        logger.error(f"セッション行書き込みエラー ({session_key}): {row_error}")
                        logger.error(f"問題のあるセッションデータ型: {type(session)}")
                        continue

        except Exception as file_error:
            logger.error(f"VPNセッションCSV書き込みエラー ({filename}): {file_error}")
            raise

    def _generate_vpn_user_summary_csv(self, vpn_data: Dict, filename: str):
        """VPNユーザーサマリーCSV生成"""
        user_summary = vpn_data.get('user_summary', {})

        fieldnames = [
            'user', 'total_sessions', 'active_sessions', 'closed_sessions', 
            'total_bytes_transfer', 'avg_session_duration', 'total_session_duration', 
            'unique_source_ips', 'unique_assign_ips', 'countries', 
            'first_connection', 'last_connection', 'source_ip_count',
            'assign_ip_count', 'country_count'
        ]

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for user, stats in user_summary.items():
                    if not isinstance(stats, dict):
                        continue

                    # 日時のフォーマット
                    first_conn = stats.get('first_connection')
                    last_conn = stats.get('last_connection')
                    first_str = first_conn.strftime('%Y-%m-%d %H:%M:%S') if first_conn else ''
                    last_str = last_conn.strftime('%Y-%m-%d %H:%M:%S') if last_conn else ''

                    # 時間の計算（時:分:秒形式）
                    avg_duration = stats.get('avg_session_duration', 0)
                    avg_duration_str = seconds_to_duration_str(avg_duration)
                    total_duration = stats.get('total_session_duration', 0)
                    total_duration_str = seconds_to_duration_str(total_duration)

                    # 安全な文字列変換関数
                    def safe_join(items, separator=', '):
                        """リスト内の要素を安全に文字列結合"""
                        if not items:
                            return ''
                        string_items = []
                        for item in items:
                            if isinstance(item, (str, int, float)):
                                string_items.append(str(item))
                            elif isinstance(item, dict):
                                string_items.append(str(item.get('name', item.get('value', str(item)))))
                            else:
                                string_items.append(str(item))
                        return separator.join(string_items)

                    # リストの処理
                    source_ips = stats.get('unique_source_ips', [])
                    assign_ips = stats.get('unique_assign_ips', [])
                    countries = stats.get('countries', [])

                    row = {
                        'user': user,
                        'total_sessions': stats.get('total_sessions', 0),
                        'active_sessions': stats.get('active_sessions', 0),
                        'closed_sessions': stats.get('closed_sessions', 0),
                        'total_bytes_transfer': f"{stats.get('total_bytes_transfer', 0):,}",
                        'avg_session_duration': avg_duration_str,
                        'total_session_duration': total_duration_str,
                        'unique_source_ips': safe_join(source_ips),
                        'unique_assign_ips': safe_join(assign_ips),
                        'countries': safe_join(countries),
                        'first_connection': first_str,
                        'last_connection': last_str,
                        'source_ip_count': len(source_ips),
                        'assign_ip_count': len(assign_ips),
                        'country_count': len(countries)
                    }
                    writer.writerow(row)

        except Exception as file_error:
            logger.error(f"VPNユーザーサマリーCSV書き込みエラー ({filename}): {file_error}")
            raise

    def _generate_general_csv(self, data: Any, filename: str):
        """汎用CSV生成（フォールバック）"""
        fieldnames = ['key', 'value']

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            if isinstance(data, dict):
                for key, value in data.items():
                    writer.writerow({'key': str(key), 'value': str(value)})
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    writer.writerow({'key': f'item_{i}', 'value': str(item)})
            else:
                writer.writerow({'key': 'data', 'value': str(data)})

class FortigateForensicAnalyzer:
    """メインのFortigateフォレンジック分析器（2025年版・設定外部化対応）"""

    def __init__(self, output_dir: str = "./forensic_output", config: ForensicConfig = None):
        self.config = config or ForensicConfig()
        self.analyzer = LogAnalyzer(self.config)
        self.report_generator = ReportGenerator(output_dir, self.config)
        self.output_dir = output_dir

        logger.info(f"=== Fortigate フォレンジック分析器 2025年版 ===")
        logger.info(f"出力ディレクトリ: {output_dir}")
        logger.info(f"監視対象:")
        logger.info(f"  - クリティカルポート: {len(self.config.CRITICAL_PORTS)}個")
        logger.info(f"  - 高リスクIP範囲: {len(self.config.HIGH_RISK_IP_RANGES)}個")
        logger.info(f"  - デフォルトチャンクサイズ: {self.config.DEFAULT_CHUNK_SIZE:,}行")

    def analyze_logs(self, log_file_path: str, target_user: str = None, chunk_size: int = None) -> Dict:
        """ログファイルを解析してフォレンジック分析を実行（メモリ効率化版・設定外部化対応）"""
        # チャンクサイズが指定されていない場合は設定から取得
        if chunk_size is None:
            chunk_size = self.config.DEFAULT_CHUNK_SIZE
            
        logger.info(f"ログファイル解析開始: {log_file_path}")
        
        # ユーザー表示ロジック
        if target_user:
            logger.info(f"対象ユーザー: {target_user}")
        else:
            logger.info(f"対象ユーザー: 全てのユーザ")
            
        logger.info(f"チャンクサイズ: {chunk_size:,}行")

        # ログファイル存在確認
        if not os.path.exists(log_file_path):
            logger.error(f"ログファイルが見つかりません: {log_file_path}")
            return {}

        # 累積統計用の変数を初期化
        all_parsed_logs = []
        total_lines_processed = 0
        
        try:
            # ストリーミング処理でファイルを読み込み
            with open(log_file_path, 'r', encoding='utf-8', buffering=8192) as f:
                chunk_lines = []
                progress_interval = self.config.MAX_PROGRESS_DISPLAY_INTERVAL
                
                for line_num, line in enumerate(f, 1):
                    chunk_lines.append(line.strip())
                    
                    # チャンクサイズに達したら処理
                    if len(chunk_lines) >= chunk_size:
                        chunk_parsed = self.analyzer.parser.parse_logs(chunk_lines, target_user)
                        all_parsed_logs.extend(chunk_parsed)
                        total_lines_processed += len(chunk_lines)
                        
                        if line_num % progress_interval == 0:  # 設定に基づく進捗表示
                            logger.info(f"処理済み行数: {total_lines_processed:,}行、解析済みログ: {len(all_parsed_logs):,}件")
                        
                        chunk_lines = []  # チャンクをクリア
                
                # 残りの行を処理
                if chunk_lines:
                    chunk_parsed = self.analyzer.parser.parse_logs(chunk_lines, target_user)
                    all_parsed_logs.extend(chunk_parsed)
                    total_lines_processed += len(chunk_lines)

        except MemoryError:
            logger.error("メモリ不足エラー。チャンクサイズを小さくして再実行してください。")
            return {}
        except Exception as e:
            logger.error(f"ログファイル読み込みエラー: {e}")
            return {}

        if not all_parsed_logs:
            logger.warning("解析対象のログが見つかりませんでした")
            return {}

        logger.info(f"総処理行数: {total_lines_processed:,}行")
        logger.info(f"解析対象ログ数: {len(all_parsed_logs):,}件")

        # 各種分析の実行（統合処理使用・エラーハンドリング強化）
        results = {}
        failed_analyses = []

        # 1&2. 宛先IP分析とサブネット分析（統合実行）
        try:
            logger.info("宛先IP・サブネット分析を実行中...")
            private_ips, global_ips, private_subnets, global_subnets = self.analyzer.analyze_destination_ips_and_subnets(all_parsed_logs)
            results['destination_ips_private'] = private_ips
            results['destination_ips_global'] = global_ips
            results['subnets_private'] = private_subnets
            results['subnets_global'] = global_subnets
            logger.info("IP・サブネット分析完了")
        except Exception as e:
            logger.error(f"IP・サブネット分析失敗: {e}")
            logger.debug(traceback.format_exc())
            failed_analyses.append('ip_subnet_analysis')
            # 空の結果で継続
            results['destination_ips_private'] = {}
            results['destination_ips_global'] = {}
            results['subnets_private'] = {}
            results['subnets_global'] = {}

        # 3. ポート分析
        try:
            logger.info("ポート分析を実行中...")
            port_analysis = self.analyzer.analyze_ports(all_parsed_logs)
            results['port_analysis'] = port_analysis
            logger.info("ポート分析完了")
        except Exception as e:
            logger.error(f"ポート分析失敗: {e}")
            logger.debug(traceback.format_exc())
            failed_analyses.append('port_analysis')
            results['port_analysis'] = {}

        # 4. タイムライン分析
        try:
            logger.info("タイムライン分析を実行中...")
            # VPNセッション情報も渡してBI分析用フィールドを生成
            vpn_sessions = results.get('vpn_analysis', {}).get('sessions', {})
            timeline = self.analyzer.timeline_analyzer.create_timeline(all_parsed_logs, vpn_sessions)
            time_patterns = self.analyzer.timeline_analyzer.analyze_time_patterns(timeline)
            results['timeline'] = timeline
            results['time_patterns'] = time_patterns
            logger.info("タイムライン分析完了")
        except Exception as e:
            logger.error(f"タイムライン分析失敗: {e}")
            logger.debug(traceback.format_exc())
            failed_analyses.append('timeline_analysis')
            results['timeline'] = []
            results['time_patterns'] = {}

        # 5. データ転送量分析
        try:
            logger.info("データ転送量分析を実行中...")
            transfer_analysis = self.analyzer.analyze_data_transfer(all_parsed_logs)
            results['data_transfer'] = transfer_analysis
            logger.info("データ転送量分析完了")
        except Exception as e:
            logger.error(f"データ転送量分析失敗: {e}")
            logger.debug(traceback.format_exc())
            failed_analyses.append('data_transfer_analysis')
            results['data_transfer'] = {}

        # 6. ジオロケーション分析
        try:
            logger.info("ジオロケーション分析を実行中...")
            geo_analysis = self.analyzer.geo_analyzer.analyze_country_stats(all_parsed_logs)
            results['geolocation'] = geo_analysis
            logger.info("ジオロケーション分析完了")
        except Exception as e:
            logger.error(f"ジオロケーション分析失敗: {e}")
            logger.debug(traceback.format_exc())
            failed_analyses.append('geolocation_analysis')
            results['geolocation'] = {}

        # 7. VPN接続分析（新機能）
        try:
            logger.info("VPN接続分析を実行中...")
            vpn_analysis = self.analyzer.vpn_analyzer.analyze_vpn_sessions(all_parsed_logs)
            results['vpn_analysis'] = vpn_analysis
            logger.info("VPN接続分析完了")
        except Exception as e:
            logger.error(f"VPN接続分析失敗: {e}")
            logger.debug(traceback.format_exc())
            failed_analyses.append('vpn_analysis')
            results['vpn_analysis'] = {}

        # 分析結果のサマリー
        if failed_analyses:
            logger.warning(f"失敗した分析: {', '.join(failed_analyses)}")
            results['failed_analyses'] = failed_analyses
        else:
            logger.info("全ての分析が正常に完了しました")

        # 8. CSV レポート生成（エラーハンドリング強化）
        try:
            self._generate_all_reports(results)
        except Exception as e:
            logger.error(f"レポート生成でエラーが発生しましたが、分析結果は保持されています: {e}")
            logger.debug(traceback.format_exc())

        logger.info("分析完了")
        return results

    def _generate_all_reports(self, results: Dict):
        """全レポートを生成（エラーハンドリング強化版）"""
        logger.info("CSVレポート生成開始")
        
        successful_reports = []
        failed_reports = []

        # レポート生成リスト
        reports = [
            ('subnets_private', "subnet_analysis_private.csv", 'subnet_private'),
            ('subnets_global', "subnet_analysis_global.csv", 'subnet_global'),
            ('destination_ips_private', "destination_ip_private.csv", 'destination_ip_private'),
            ('destination_ips_global', "destination_ip_global.csv", 'destination_ip_global'),
            ('port_analysis', "port_analysis.csv", 'port_analysis'),
            ('timeline', "timeline_analysis.csv", 'timeline'),
            ('data_transfer', "data_transfer_analysis.csv", 'data_transfer'),
            ('geolocation', "geolocation_analysis.csv", 'geolocation'),
            ('vpn_analysis', "vpn_sessions.csv", 'vpn_sessions'),  # VPNセッション詳細
            ('vpn_analysis', "vpn_user_summary.csv", 'vpn_user_summary')  # VPNユーザーサマリー
        ]

        for data_key, filename, report_type in reports:
            try:
                if results.get(data_key):
                    full_filename = os.path.join(self.output_dir, filename)
                    self.report_generator.generate_csv_report(
                        results[data_key], full_filename, report_type
                    )
                    successful_reports.append(filename)
                    logger.info(f"✓ {report_type} レポート生成成功: {filename}")
                else:
                    logger.warning(f"⚠ {report_type} のデータが空のため、レポートをスキップしました")
            except Exception as e:
                logger.error(f"✗ {report_type} レポート生成失敗: {e}")
                failed_reports.append((filename, str(e)))

        # 結果サマリー
        total_reports = len(reports)
        success_count = len(successful_reports)
        
        logger.info(f"レポート生成完了: {success_count}/{total_reports} 成功")
        
        if failed_reports:
            logger.warning("失敗したレポート:")
            for filename, error in failed_reports:
                logger.warning(f"  - {filename}: {error}")
        
        if success_count == 0:
            logger.error("すべてのレポート生成に失敗しました")
        elif failed_reports:
            logger.warning("一部のレポート生成に失敗しましたが、分析は継続されました")
        else:
            logger.info("すべてのレポートが正常に生成されました")

    def _extract_high_risk_findings(self, results: Dict) -> Dict:
        """高リスクな発見事項を抽出"""
        high_risk = {
            'high_risk_private_ips': [],
            'high_volume_transfers': [],
        }

        # 高リスクプライベートIP
        for ip, stats in results.get('destination_ips_private', {}).items():
            if stats.get('is_high_risk', False):
                high_risk['high_risk_private_ips'].append({
                    'ip': ip,
                    'connections': stats.get('connection_count', 0),
                    'total_bytes': stats.get('total_bytes_sent', 0) + stats.get('total_bytes_received', 0)
                })

        # 大容量転送（上位10件）
        transfer_data = results.get('data_transfer', {})
        high_volume = sorted(
            [(ip, stats) for ip, stats in transfer_data.items()],
            key=lambda x: x[1].get('total_transfer', 0),
            reverse=True
        )[:10]

        for ip, stats in high_volume:
            high_risk['high_volume_transfers'].append({
                'ip': ip,
                'total_bytes': stats.get('total_transfer', 0),
                'sessions': stats.get('session_count', 0)
            })

        return high_risk

def main():
    """メイン実行関数（2025年版・設定外部化対応）"""
    import argparse

    # 設定を読み込み
    config = ForensicConfig()

    parser = argparse.ArgumentParser(
        description='Fortigate SSL-VPN フォレンジック分析ツール 2025年版',
        epilog=f"""
設定情報:
  - 監視ポート数: {len(config.CRITICAL_PORTS) + len(config.ADMIN_PORTS) + len(config.STANDARD_PORTS)}個
  - クリティカルポート: {len(config.CRITICAL_PORTS)}個
  - 高リスクIP範囲: {len(config.HIGH_RISK_IP_RANGES)}個
  - デフォルトチャンク: {config.DEFAULT_CHUNK_SIZE:,}行
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('log_file', help='解析対象のログファイルパス')
    parser.add_argument('--user', '-u', default=None, help='対象ユーザー名（未指定の場合: 全てのユーザ）')
    parser.add_argument('--output', '-o', default='./forensic_output', help='出力ディレクトリ（デフォルト: ./forensic_output）')
    parser.add_argument('--chunk-size', '-c', type=int, default=config.DEFAULT_CHUNK_SIZE, 
                       help=f'ログファイル読み込みチャンクサイズ（デフォルト: {config.DEFAULT_CHUNK_SIZE:,}行）')

    args = parser.parse_args()

    # フォレンジック分析実行（設定付き）
    analyzer = FortigateForensicAnalyzer(args.output, config)
    results = analyzer.analyze_logs(args.log_file, args.user, args.chunk_size)

    if results:
        print(f"\n=== 分析完了 ===")
        print(f"対象ユーザー: {args.user if args.user else '全てのユーザ'}")
        print(f"出力ディレクトリ: {args.output}")
        print(f"プライベートサブネット数: {len(results.get('subnets_private', {}))}")
        print(f"グローバルサブネット数: {len(results.get('subnets_global', {}))}")
        print(f"プライベートIP数: {len(results.get('destination_ips_private', {}))}")
        print(f"グローバルIP数: {len(results.get('destination_ips_global', {}))}")
        print(f"タイムラインイベント数: {len(results.get('timeline', []))}")
        
        # VPN分析結果の表示
        vpn_data = results.get('vpn_analysis', {})
        if vpn_data:
            sessions = vpn_data.get('sessions', {})
            users = vpn_data.get('user_summary', {})
            print(f"VPNセッション数: {len(sessions)}")
            print(f"VPN利用ユーザー数: {len(users)}")
        
        print("\n詳細な分析結果は出力ディレクトリのCSVファイルをご確認ください。")
    else:
        print("分析に失敗しました。ログファイルとユーザー名を確認してください。")

if __name__ == "__main__":
    main()

