"""
PhishBuster - Phishing URL Scanner (Conceito B)
Análise heurística completa com validação de segurança
"""
import re
import ssl
import socket
import whois
import requests
from datetime import datetime
from urllib.parse import urlparse, quote
from typing import Dict, List
import dns.resolver
from Levenshtein import distance as levenshtein_distance
from bs4 import BeautifulSoup
import hashlib
import json
import gzip
from io import BytesIO
import os
from pathlib import Path

# Domínios confiáveis que não devem ser penalizados por redirecionamentos
TRUSTED_DOMAINS = {
    'google.com', 'www.google.com', 'youtube.com', 'www.youtube.com',
    'facebook.com', 'www.facebook.com', 'instagram.com', 'www.instagram.com',
    'twitter.com', 'www.twitter.com', 'x.com', 'www.x.com',
    'amazon.com', 'www.amazon.com', 'microsoft.com', 'www.microsoft.com',
    'apple.com', 'www.apple.com', 'linkedin.com', 'www.linkedin.com',
    'github.com', 'www.github.com', 'stackoverflow.com', 'www.stackoverflow.com',
    'wikipedia.org', 'www.wikipedia.org', 'reddit.com', 'www.reddit.com',
    'netflix.com', 'www.netflix.com', 'paypal.com', 'www.paypal.com',
    'ebay.com', 'www.ebay.com', 'adobe.com', 'www.adobe.com'
}
import json


class PhishingScanner:
    """Scanner seguro para detecção de phishing por análise heurística"""
    
    LEGITIMATE_DOMAINS = [
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'paypal.com', 'netflix.com', 'instagram.com',
        'twitter.com', 'linkedin.com', 'github.com', 'yahoo.com',
        'ebay.com', 'wikipedia.org', 'reddit.com', 'adobe.com',
        'mercadolivre.com.br', 'nubank.com.br', 'itau.com.br',
        'bradesco.com.br', 'santander.com.br', 'caixa.gov.br'
    ]
    
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'account', 'verify', 'secure', 'update',
        'confirm', 'banking', 'password', 'suspended', 'urgent',
        'alert', 'security', 'blocked', 'expired', 'limited',
        'validate', 'restore', 'unusual', 'activity', 'unlock'
    ]
    
    # Variações suspeitas de palavras (typos intencionais comuns em phishing)
    SUSPICIOUS_WORD_VARIANTS = {
        'secur': 'secure/security',  # ulys-securs.com
        'verrify': 'verify',
        'confirrm': 'confirm',
        'acccount': 'account',
        'bankinng': 'banking',
        'loggin': 'login',
        'secutiry': 'security',
        'verificacion': 'verification',
        'authentification': 'authentication'
    }
    
    HIGH_RISK_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Domínios gratuitos (Freenom)
        '.pw', '.cc', '.info', '.biz', '.xyz',  # Comuns em phishing
        '.top', '.win', '.bid', '.vip', '.loan',  # Spam domains
        '.club', '.online', '.site', '.website',  # Genéricos baratos
        '.sbs', '.icu', '.cyou', '.tokyo', '.buzz'  # Novos TLDs de risco
    ]
    
    DYNAMIC_DNS_PROVIDERS = [
        'no-ip', 'dyndns', 'ddns', 'dynu', 'freedns', 
        'afraid.org', 'changeip', 'dnsdynamic'
    ]
    
    def __init__(self):
        self.features = {}
        self.risk_score = 0
        self.risk_factors = []
        
    def analyze_url(self, url: str) -> Dict:
        """
        Análise SEGURA de URL sem fazer requisições HTTP
        """
        self.features = {}
        self.risk_score = 0
        self.risk_factors = []
        
        try:
            # Parse URL
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            # Fase 1: Análises heurísticas básicas (100% seguro, sem acessar URL)
            self._analyze_url_structure(url, parsed, domain, path)
            self._analyze_domain_patterns(domain)
            self._analyze_suspicious_keywords(url)
            self._analyze_typosquatting(domain)
            self._check_ip_address(domain)
            self._check_port_numbers(parsed)
            self._analyze_subdomain_depth(domain)
            self._check_url_shorteners(domain)
            self._check_phishing_databases(url, domain)
            self._analyze_path_patterns(path, url)
            
            # Fase 2: Análises avançadas (CONCEITO B - apenas se score inicial < 70)
            # Só acessa domínios com score inicial baixo para evitar contaminar sistema
            initial_score = sum(factor['score'] for factor in self.risk_factors)
            
            if initial_score < 70:  # Domínio parece legítimo, seguro consultar
                self._analyze_domain_age(domain)
                self._analyze_dns(domain)
                self._analyze_ssl_certificate(domain)
                self._analyze_redirects(url)
                self._analyze_content(url)
            else:
                # Score alto = muito suspeito, NÃO acessar
                self.features['advanced_analysis_skipped'] = True
                self.features['advanced_analysis_reason'] = 'Score inicial muito alto - URL suspeita'
            
            # Calcula score final
            self._calculate_risk_score()
            
            return {
                'url': url,
                'domain': domain,
                'risk_score': self.risk_score,
                'total_risk_score': self.total_risk_score,
                'risk_level': self._get_risk_level(),
                'is_phishing': self.risk_score >= 50,
                'features': self.features,
                'risk_factors': self.risk_factors,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'risk_score': 0,
                'risk_level': 'unknown'
            }
    
    def _analyze_url_structure(self, url: str, parsed, domain: str, path: str) -> None:
        """Analisa estrutura da URL"""
        
        # Comprimento da URL
        url_length = len(url)
        self.features['url_length'] = url_length
        
        if url_length > 100:
            self.risk_factors.append({
                'factor': 'URL extremamente longa',
                'severity': 'high',
                'score': 25,
                'detail': f'{url_length} caracteres (URLs legítimas geralmente < 100)'
            })
        elif url_length > 75:
            self.risk_factors.append({
                'factor': 'URL muito longa',
                'severity': 'medium',
                'score': 15,
                'detail': f'{url_length} caracteres'
            })
        
        # @ na URL (técnica de obscurecimento)
        if '@' in url:
            self.features['has_at_symbol'] = True
            self.risk_factors.append({
                'factor': 'Símbolo @ na URL',
                'severity': 'critical',
                'score': 40,
                'detail': 'Técnica de obscurecimento - tudo antes do @ é ignorado'
            })
        else:
            self.features['has_at_symbol'] = False
        
        # Múltiplas barras no path
        slash_count = path.count('//')
        if slash_count > 0:
            self.risk_factors.append({
                'factor': 'Barras duplas no caminho',
                'severity': 'medium',
                'score': 10,
                'detail': 'Pode indicar tentativa de confusão'
            })
        
        # Uso de HTTPS
        if parsed.scheme == 'https':
            self.features['uses_https'] = True
        else:
            self.features['uses_https'] = False
            
            # Não penaliza domínios confiáveis por falta de HTTPS
            # (usuário pode ter digitado sem https://, mas o site redireciona automaticamente)
            domain_normalized = domain.replace('www.', '')
            is_trusted = domain.lower() in TRUSTED_DOMAINS or domain_normalized.lower() in TRUSTED_DOMAINS
            
            if not is_trusted:
                self.risk_factors.append({
                    'factor': 'Não usa HTTPS',
                    'severity': 'high',
                    'score': 20,
                    'detail': 'Sites legítimos usam HTTPS para segurança'
                })
        
        # Muitos hífens no domínio
        hyphen_count = domain.count('-')
        self.features['hyphen_count'] = hyphen_count
        if hyphen_count >= 4:
            self.risk_factors.append({
                'factor': 'Muitos hífens no domínio',
                'severity': 'high',
                'score': 20,
                'detail': f'{hyphen_count} hífens (domínios legítimos raramente têm tantos)'
            })
        elif hyphen_count >= 2:
            self.risk_factors.append({
                'factor': 'Vários hífens no domínio',
                'severity': 'medium',
                'score': 10,
                'detail': f'{hyphen_count} hífens'
            })
        
        # Números no domínio
        numbers_count = sum(c.isdigit() for c in domain)
        self.features['numbers_in_domain'] = numbers_count
        if numbers_count >= 3:
            self.risk_factors.append({
                'factor': 'Muitos números no domínio',
                'severity': 'high',
                'score': 25,
                'detail': f'{numbers_count} números (possível substituição de caracteres)'
            })
        elif numbers_count > 0:
            self.risk_factors.append({
                'factor': 'Números no domínio',
                'severity': 'medium',
                'score': 12,
                'detail': 'Pode indicar imitação de marca (ex: paypa1)'
            })
        
        # Detecta mix estranho de números e letras (ex: b0k8dq)
        # Pega o nome principal do domínio, ignorando www e subdomínios comuns
        domain_parts = domain.split('.')
        domain_main = domain_parts[0]
        if domain_main in ['www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'm', 'mobile'] and len(domain_parts) > 1:
            domain_main = domain_parts[1]
        
        if len(domain_main) >= 6:
            num_count = sum(c.isdigit() for c in domain_main)
            if 2 <= num_count <= len(domain_main) - 2:  # Mix de números e letras
                self.risk_factors.append({
                    'factor': 'Domínio com caracteres aleatórios',
                    'severity': 'high',
                    'score': 25,
                    'detail': f'Domínio "{domain_main}" parece gerado aleatoriamente'
                })
    
    def _analyze_domain_patterns(self, domain: str) -> None:
        """Analisa padrões suspeitos no domínio"""
        
        # TLDs de alto risco
        domain_lower = domain.lower()
        for tld in self.HIGH_RISK_TLDS:
            if domain_lower.endswith(tld):
                self.features['high_risk_tld'] = tld
                self.risk_factors.append({
                    'factor': 'TLD de alto risco',
                    'severity': 'high',
                    'score': 30,
                    'detail': f'Domínio {tld} é frequentemente usado em phishing'
                })
                break
        else:
            self.features['high_risk_tld'] = None
        
        # Domínio muito curto (menos de 5 caracteres antes do TLD)
        domain_parts = domain_lower.split('.')
        if len(domain_parts) >= 2:
            # Ignora subdomínios comuns (www, mail, ftp, etc) para pegar o nome real
            main_name = domain_parts[0]
            if main_name in ['www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'm', 'mobile'] and len(domain_parts) > 2:
                main_name = domain_parts[1]  # Pega o próximo nível
            
            if len(main_name) < 5 and main_name not in ['www', 'mail', 'ftp', 'smtp', 'gov', 'edu', 'org', 'com', 'net']:
                self.risk_factors.append({
                    'factor': 'Domínio muito curto',
                    'severity': 'medium',
                    'score': 15,
                    'detail': f'Nome principal "{main_name}" tem apenas {len(main_name)} caracteres'
                })
        
        # DNS dinâmico
        for provider in self.DYNAMIC_DNS_PROVIDERS:
            if provider in domain_lower:
                self.features['uses_dynamic_dns'] = True
                self.risk_factors.append({
                    'factor': 'DNS dinâmico gratuito',
                    'severity': 'high',
                    'score': 30,
                    'detail': f'Usa {provider} - comum em phishing pois é gratuito'
                })
                break
        else:
            self.features['uses_dynamic_dns'] = False
        
        # Padrão de marca + palavra suspeita
        brand_keywords = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 
                         'facebook', 'netflix', 'bank', 'itau', 'bradesco']
        
        for brand in brand_keywords:
            if brand in domain_lower and domain_lower != f'{brand}.com':
                # Verifica se tem palavra suspeita junto
                if any(word in domain_lower for word in ['secure', 'login', 'verify', 'account']):
                    self.risk_factors.append({
                        'factor': 'Marca + palavra suspeita',
                        'severity': 'critical',
                        'score': 35,
                        'detail': f'Domínio contém "{brand}" + palavra suspeita (ex: paypal-secure)'
                    })
                    break
        
        # Detecta variações suspeitas de palavras (typos intencionais)
        for variant, original in self.SUSPICIOUS_WORD_VARIANTS.items():
            if variant in domain_lower:
                self.risk_factors.append({
                    'factor': 'Variação suspeita de palavra',
                    'severity': 'high',
                    'score': 30,
                    'detail': f'Domínio contém "{variant}" (possível typo de "{original}")'
                })
                break
        
        # Hífen + palavra de segurança (comum em phishing)
        if '-' in domain_lower:
            security_words = ['secur', 'safe', 'protect', 'verify', 'auth', 'valid', 'confirm', 'trust']
            for word in security_words:
                if word in domain_lower:
                    self.risk_factors.append({
                        'factor': 'Hífen + palavra de segurança',
                        'severity': 'high',
                        'score': 25,
                        'detail': f'Domínio com hífen contém palavra relacionada a segurança ("{word}")'
                    })
                    break
    
    def _analyze_suspicious_keywords(self, url: str) -> None:
        """Detecta palavras suspeitas na URL"""
        
        url_lower = url.lower()
        found_keywords = []
        
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                found_keywords.append(keyword)
        
        self.features['suspicious_keywords'] = found_keywords
        keyword_count = len(found_keywords)
        
        if keyword_count >= 3:
            self.risk_factors.append({
                'factor': 'Múltiplas palavras suspeitas',
                'severity': 'high',
                'score': 20,
                'detail': f'Encontradas: {", ".join(found_keywords[:3])}'
            })
        elif keyword_count >= 1:
            self.risk_factors.append({
                'factor': 'Palavras suspeitas na URL',
                'severity': 'medium',
                'score': 10 * keyword_count,
                'detail': f'Encontradas: {", ".join(found_keywords)}'
            })
    
    def _analyze_typosquatting(self, domain: str) -> None:
        """Detecta typosquatting usando distância de Levenshtein"""
        
        # Extrai domínio principal
        parts = domain.split('.')
        if len(parts) >= 2:
            main_domain = '.'.join(parts[-2:])
        else:
            main_domain = domain
        
        min_distance = float('inf')
        closest_domain = None
        
        for legit_domain in self.LEGITIMATE_DOMAINS:
            dist = levenshtein_distance(main_domain.lower(), legit_domain.lower())
            if dist < min_distance:
                min_distance = dist
                closest_domain = legit_domain
        
        self.features['closest_legitimate_domain'] = closest_domain
        self.features['levenshtein_distance'] = min_distance
        
        # Detecção de typosquatting
        if min_distance == 0:
            # Domínio legítimo
            pass
        elif 1 <= min_distance <= 2:
            self.risk_factors.append({
                'factor': 'Typosquatting CRÍTICO',
                'severity': 'critical',
                'score': 50,
                'detail': f'Muito similar a "{closest_domain}" (distância: {min_distance})'
            })
        elif 3 <= min_distance <= 4:
            self.risk_factors.append({
                'factor': 'Possível typosquatting',
                'severity': 'high',
                'score': 30,
                'detail': f'Similar a "{closest_domain}" (distância: {min_distance})'
            })
    
    def _check_ip_address(self, domain: str) -> None:
        """Verifica se usa IP ao invés de domínio"""
        
        # IPv4
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        # IPv6
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        if re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain):
            self.features['uses_ip'] = True
            self.risk_factors.append({
                'factor': 'Usa endereço IP',
                'severity': 'critical',
                'score': 40,
                'detail': 'Sites legítimos usam nomes de domínio, não IPs'
            })
        else:
            self.features['uses_ip'] = False
    
    def _check_port_numbers(self, parsed) -> None:
        """Verifica portas não-padrão"""
        
        if parsed.port:
            # Portas padrão: 80 (HTTP), 443 (HTTPS)
            if parsed.port not in [80, 443]:
                self.features['uses_non_standard_port'] = True
                self.risk_factors.append({
                    'factor': 'Porta não-padrão',
                    'severity': 'high',
                    'score': 25,
                    'detail': f'Porta {parsed.port} (sites legítimos usam 80 ou 443)'
                })
            else:
                self.features['uses_non_standard_port'] = False
        else:
            self.features['uses_non_standard_port'] = False
    
    def _analyze_subdomain_depth(self, domain: str) -> None:
        """Analisa profundidade de subdomínios"""
        
        dots_count = domain.count('.')
        self.features['subdomain_depth'] = dots_count
        
        if dots_count >= 4:
            self.risk_factors.append({
                'factor': 'Muitos subdomínios',
                'severity': 'high',
                'score': 20,
                'detail': f'{dots_count} níveis (ex: a.b.c.d.com) - suspeito'
            })
        elif dots_count >= 3:
            self.risk_factors.append({
                'factor': 'Vários subdomínios',
                'severity': 'medium',
                'score': 10,
                'detail': f'{dots_count} níveis de subdomínio'
            })
    
    def _check_url_shorteners(self, domain: str) -> None:
        """Detecta encurtadores de URL"""
        
        url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'short.link'
        ]
        
        domain_lower = domain.lower()
        for shortener in url_shorteners:
            if shortener in domain_lower:
                self.features['is_url_shortener'] = True
                self.risk_factors.append({
                    'factor': 'Encurtador de URL',
                    'severity': 'medium',
                    'score': 15,
                    'detail': f'Usa {shortener} - oculta destino real'
                })
                break
        else:
            self.features['is_url_shortener'] = False
    
    def _analyze_path_patterns(self, path: str, url: str) -> None:
        """
        Analisa padrões suspeitos no caminho da URL
        """
        if not path or path == '/':
            return
        
        path_lower = path.lower()
        
        # Paths muito longos
        if len(path) > 100:
            self.risk_factors.append({
                'factor': 'Path extremamente longo',
                'severity': 'medium',
                'score': 15,
                'detail': f'Caminho com {len(path)} caracteres'
            })
        
        # Caracteres aleatórios no path (ex: /sbn3xcyf/hC2dZi/)
        path_segments = [p for p in path.split('/') if p]
        for segment in path_segments:
            if len(segment) >= 6:
                # Verifica se parece aleatório (mix de maiúsculas, minúsculas, números)
                has_upper = any(c.isupper() for c in segment)
                has_lower = any(c.islower() for c in segment)
                has_digit = any(c.isdigit() for c in segment)
                
                if (has_upper and has_lower and has_digit) or \
                   (has_upper and has_lower and len(segment) >= 8):
                    self.risk_factors.append({
                        'factor': 'Path com caracteres aleatórios',
                        'severity': 'high',
                        'score': 25,
                        'detail': f'Segmento "{segment}" parece gerado aleatoriamente'
                    })
                    break
    
    def _check_phishing_databases(self, url: str, domain: str) -> None:
        """
        Verifica URL contra bases de phishing conhecidas (CONCEITO C)
        PhishTank: atualiza a cada 4 horas | OpenPhish: consulta em tempo real
        """
        self.features['in_phishtank'] = False
        self.features['in_openphish'] = False
        
        # PHISHTANK - Atualiza cache a cada 4 horas
        cache_file = Path('phishtank_cache.json')
        data = None
        cache_info = ""
        should_update = True
        
        # Verifica se cache existe e está dentro do prazo de 4 horas
        if cache_file.exists():
            cache_age_hours = (datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)).total_seconds() / 3600
            
            if cache_age_hours < 4:
                # Cache válido - usa sem baixar novamente
                should_update = False
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    cache_info = f" (cache: {cache_age_hours:.1f}h atrás)"
                except:
                    # Erro ao ler - tenta atualizar
                    should_update = True
        
        # Baixa base atualizada se necessário (>4h ou sem cache)
        if should_update:
            try:
                response = requests.get(
                    'http://data.phishtank.com/data/online-valid.json.gz',
                    timeout=15,
                    headers={'User-Agent': 'phishtank/PhishBuster'}
                )
                
                if response.status_code == 200:
                    # Descompacta e salva
                    with gzip.GzipFile(fileobj=BytesIO(response.content)) as gz:
                        data = json.loads(gz.read().decode('utf-8'))
                    with open(cache_file, 'w', encoding='utf-8') as f:
                        json.dump(data, f)
                    cache_info = " (atualizado agora)"
                    
                elif response.status_code == 429:
                    # Rate limit - usa cache antigo se existir
                    if cache_file.exists():
                        try:
                            with open(cache_file, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                            cache_info = " (cache antigo - rate limit)"
                        except:
                            pass
                    
                    if not data:
                        self.risk_factors.append({
                            'factor': 'ℹ️ PhishTank indisponível',
                            'severity': 'info',
                            'score': 0,
                            'detail': 'Limite de requisições atingido. Aguarde algumas horas para nova tentativa.'
                        })
            except:
                # Erro na conexão - tenta usar cache antigo
                if cache_file.exists():
                    try:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        cache_info = " (cache - PhishTank offline)"
                    except:
                        self.risk_factors.append({
                            'factor': 'ℹ️ PhishTank offline',
                            'severity': 'info',
                            'score': 0,
                            'detail': 'Não foi possível conectar à base PhishTank'
                        })
        
        # Busca na base PhishTank
        if data:
            url_norm = url.lower().strip().rstrip('/')
            domain_norm = domain.lower().strip()
            
            for entry in data:
                phish_url = entry.get('url', '').lower().strip().rstrip('/')
                if url_norm == phish_url or domain_norm in phish_url:
                    self.features['in_phishtank'] = True
                    self.risk_factors.append({
                        'factor': f'🚨 CONFIRMADO no PhishTank{cache_info}',
                        'severity': 'critical',
                        'score': 60,
                        'detail': f"URL #{entry.get('phish_id')} verificada como phishing ativo (alvo: {entry.get('target', 'N/A')})"
                    })
                    return
        
        # OPENPHISH - Feed público em tempo real
        try:
            response = requests.get('https://openphish.com/feed.txt', timeout=10)
            
            if response.status_code == 200:
                urls = response.text.strip().split('\n')
                url_norm = url.lower().strip().rstrip('/')
                
                for phish_url in urls:
                    phish_url_clean = phish_url.lower().strip().rstrip('/')
                    if url_norm == phish_url_clean or domain.lower() in phish_url_clean:
                        self.features['in_openphish'] = True
                        self.risk_factors.append({
                            'factor': '🚨 CONFIRMADO no OpenPhish',
                            'severity': 'critical',
                            'score': 60,
                            'detail': 'URL está listada no feed OpenPhish de phishing ativo'
                        })
                        return
        except:
            pass
    
    def _analyze_domain_age(self, domain: str) -> None:
        """
        Análise de idade do domínio via WHOIS (CONCEITO B - OBRIGATÓRIO)
        """
        try:
            w = whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                # Remove timezone info se houver para evitar erro de comparação
                if hasattr(creation_date, 'replace'):
                    creation_date = creation_date.replace(tzinfo=None)
                
                now = datetime.now()
                age_days = (now - creation_date).days
                self.features['domain_age_days'] = age_days
                
                if age_days < 30:
                    self.risk_factors.append({
                        'factor': 'Domínio muito novo',
                        'severity': 'critical',
                        'score': 30,
                        'detail': f'Criado há apenas {age_days} dias'
                    })
                elif age_days < 180:
                    self.risk_factors.append({
                        'factor': 'Domínio recente',
                        'severity': 'high',
                        'score': 20,
                        'detail': f'Criado há {age_days} dias (menos de 6 meses)'
                    })
                elif age_days < 365:
                    self.risk_factors.append({
                        'factor': 'Domínio relativamente novo',
                        'severity': 'medium',
                        'score': 10,
                        'detail': f'Criado há {age_days} dias (menos de 1 ano)'
                    })
            else:
                self.features['domain_age_days'] = None
                
        except Exception as e:
            self.features['domain_age_days'] = None
            self.features['whois_error'] = str(e)
    
    def _analyze_dns(self, domain: str) -> None:
        """
        Análise de DNS (CONCEITO B)
        """
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ip_addresses = [str(rdata) for rdata in answers]
            self.features['ip_addresses'] = ip_addresses
            self.features['ip_count'] = len(ip_addresses)
            
            # Múltiplos IPs podem ser legítimos (CDN) ou suspeito
            if len(ip_addresses) > 10:
                self.risk_factors.append({
                    'factor': 'Muitos endereços IP',
                    'severity': 'medium',
                    'score': 5,
                    'detail': f'{len(ip_addresses)} IPs diferentes (pode indicar infraestrutura instável)'
                })
                
        except Exception as e:
            self.features['dns_error'] = str(e)
            self.features['ip_count'] = 0
    
    def _analyze_ssl_certificate(self, domain: str) -> None:
        """
        Análise de certificado SSL (CONCEITO B - OBRIGATÓRIO)
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.features['has_valid_ssl'] = True
                    
                    # Verifica emissor
                    issuer = dict(x[0] for x in cert['issuer'])
                    self.features['ssl_issuer'] = issuer.get('organizationName', 'Unknown')
                    
                    # Verifica se é autoassinado
                    subject = dict(x[0] for x in cert['subject'])
                    if issuer == subject:
                        self.risk_factors.append({
                            'factor': 'Certificado SSL autoassinado',
                            'severity': 'high',
                            'score': 25,
                            'detail': 'Certificado não emitido por autoridade confiável'
                        })
                    
                    # Verifica expiração
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    self.features['ssl_days_until_expiry'] = days_until_expiry
                    
                    if days_until_expiry < 0:
                        self.risk_factors.append({
                            'factor': 'Certificado SSL expirado',
                            'severity': 'critical',
                            'score': 35,
                            'detail': f'Expirado há {abs(days_until_expiry)} dias'
                        })
                    elif days_until_expiry < 30:
                        self.risk_factors.append({
                            'factor': 'Certificado SSL prestes a expirar',
                            'severity': 'medium',
                            'score': 10,
                            'detail': f'Expira em {days_until_expiry} dias'
                        })
                        
        except ssl.SSLError:
            self.features['has_valid_ssl'] = False
            self.risk_factors.append({
                'factor': 'SSL inválido ou ausente',
                'severity': 'high',
                'score': 25,
                'detail': 'Sem certificado HTTPS válido'
            })
        except Exception as e:
            self.features['has_valid_ssl'] = None
            self.features['ssl_error'] = str(e)
    
    def _analyze_redirects(self, url: str) -> None:
        """
        Detecção de redirecionamentos suspeitos (CONCEITO B - OBRIGATÓRIO)
        """
        try:
            response = requests.get(url, allow_redirects=True, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            redirect_count = len(response.history)
            self.features['redirect_count'] = redirect_count
            
            if redirect_count > 4:
                self.risk_factors.append({
                    'factor': 'Muitos redirecionamentos',
                    'severity': 'high',
                    'score': 20,
                    'detail': f'{redirect_count} redirecionamentos (suspeito)'
                })
            elif redirect_count > 2:
                self.risk_factors.append({
                    'factor': 'Múltiplos redirecionamentos',
                    'severity': 'medium',
                    'score': 10,
                    'detail': f'{redirect_count} redirecionamentos'
                })
            
            # Verifica se domínio final é diferente
            if response.url != url:
                final_domain = urlparse(response.url).netloc
                original_domain = urlparse(url).netloc
                
                # Remove 'www.' para comparação normalizada
                final_domain_normalized = final_domain.replace('www.', '')
                original_domain_normalized = original_domain.replace('www.', '')
                
                # Só penaliza se os domínios base forem realmente diferentes
                if final_domain_normalized != original_domain_normalized:
                    # Verifica se ambos são domínios confiáveis
                    is_original_trusted = original_domain.lower() in TRUSTED_DOMAINS or original_domain_normalized.lower() in TRUSTED_DOMAINS
                    is_final_trusted = final_domain.lower() in TRUSTED_DOMAINS or final_domain_normalized.lower() in TRUSTED_DOMAINS
                    
                    # Só penaliza se não forem ambos confiáveis
                    if not (is_original_trusted and is_final_trusted):
                        self.risk_factors.append({
                            'factor': 'Redirecionamento para domínio diferente',
                            'severity': 'high',
                            'score': 18,
                            'detail': f'Redireciona para: {final_domain}'
                        })
                    
        except Exception as e:
            self.features['redirect_error'] = str(e)
            self.features['redirect_count'] = None
    
    def _analyze_content(self, url: str) -> None:
        """
        Análise básica de conteúdo HTML (CONCEITO B - OBRIGATÓRIO)
        Detecta formulários de login e solicitações de informações sensíveis
        """
        try:
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Detecta formulários
            forms = soup.find_all('form')
            self.features['forms_count'] = len(forms)
            
            has_password_field = False
            has_sensitive_input = False
            
            for form in forms:
                # Verifica campos de senha
                if form.find_all('input', {'type': 'password'}):
                    has_password_field = True
                
                # Verifica campos sensíveis
                inputs = form.find_all('input')
                for inp in inputs:
                    input_name = inp.get('name', '').lower()
                    if any(keyword in input_name for keyword in ['email', 'user', 'login', 'pass', 'credit', 'card', 'cvv', 'ssn']):
                        has_sensitive_input = True
                        break
            
            self.features['has_password_field'] = has_password_field
            self.features['has_sensitive_input'] = has_sensitive_input
            
            if has_password_field:
                self.risk_factors.append({
                    'factor': 'Formulário de login detectado',
                    'severity': 'medium',
                    'score': 15,
                    'detail': 'Página solicita senha (comum em phishing)'
                })
            
            if has_sensitive_input:
                self.risk_factors.append({
                    'factor': 'Solicita informações sensíveis',
                    'severity': 'high',
                    'score': 20,
                    'detail': 'Formulário pede dados financeiros ou pessoais'
                })
            
            # Verifica logos de marcas conhecidas (possível imitação)
            # Apenas marcas que indicam phishing bancário/pagamento - exclui redes sociais
            brand_keywords = ['paypal', 'amazon', 'microsoft', 'apple', 'bank', 'itau', 'bradesco', 'santander', 'nubank', 'mercadopago']
            images = soup.find_all('img', src=True)
            
            # Extrai domínio atual para verificar se é o site legítimo da marca
            current_domain = urlparse(url).netloc.lower().replace('www.', '')
            
            brand_logo_found = False
            for img in images:
                src = img.get('src', '').lower()
                alt = img.get('alt', '').lower()
                
                # Ignora ícones de redes sociais (geralmente são links externos legítimos)
                # Foca apenas em logos incorporados que imitam bancos/serviços de pagamento
                is_social_icon = any(social in src for social in ['facebook', 'instagram', 'twitter', 'linkedin', 'youtube', 'whatsapp', 'telegram'])
                
                if not is_social_icon:
                    # Verifica se tem logo de marca financeira/importante
                    for brand in brand_keywords:
                        if brand in src or brand in alt:
                            # Só penaliza se NÃO for o domínio legítimo da marca
                            # Ex: google.com pode ter logo do Google, mas fake-site.com não deveria
                            if brand not in current_domain:
                                self.features['has_brand_logos'] = True
                                brand_logo_found = True
                                self.risk_factors.append({
                                    'factor': 'Uso de logos de marcas conhecidas',
                                    'severity': 'medium',
                                    'score': 12,
                                    'detail': f'Página usa logo de "{brand}" mas domínio é "{current_domain}" (possível imitação)'
                                })
                            break
                if brand_logo_found:
                    break
            
        except Exception as e:
            self.features['content_analysis_error'] = str(e)
    
    def _calculate_risk_score(self) -> None:
        """Calcula score final de risco"""
        
        total_score = sum(factor['score'] for factor in self.risk_factors)
        
        # Salva o score total real (pode ultrapassar 100)
        self.total_risk_score = total_score
        
        # Normaliza para 0-100 para classificação
        self.risk_score = min(100, total_score)
        
        # Ajuste: domínios totalmente legítimos (distância 0) têm score baixo
        if self.features.get('levenshtein_distance') == 0 and not self.risk_factors:
            self.risk_score = 0
            self.total_risk_score = 0
    
    def _get_risk_level(self) -> str:
        """Converte score para nível de risco"""
        # Se o score total ultrapassar 100, é MUITO CRÍTICO
        if self.total_risk_score > 100:
            return 'very_critical'
        elif self.risk_score >= 75:
            return 'critical'
        elif self.risk_score >= 50:
            return 'high'
        elif self.risk_score >= 25:
            return 'medium'
        else:
            return 'low'
