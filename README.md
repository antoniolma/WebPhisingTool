# 🎯 PhishBuster - Ferramenta de Detecção de Phishing

## 📋 Conceito B - Análise Heurística Segura

**PhishBuster** é uma ferramenta de detecção de phishing que analisa URLs de forma **SEGURA**, sem acessar diretamente sites suspeitos, protegendo seu computador de possíveis ameaças.

---

## ✨ Funcionalidades (Conceito B)

### 🔒 Análise 100% Segura
- **NÃO acessa URLs suspeitas** - Apenas análise de padrões
- Proteção completa contra contaminação do sistema
- Análise baseada em características da URL

### 🎯 Detecção Heurística Avançada

1. **Typosquatting Detection**
   - Usa algoritmo de Levenshtein para detectar URLs similares a sites legítimos
   - Exemplos: `paypa1.com` vs `paypal.com`, `g00gle.com` vs `google.com`
   - Score alto para distâncias de 1-2 caracteres

2. **TLDs de Alto Risco**
   - Detecta domínios gratuitos (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`)
   - Identifica extensões comumente usadas em phishing (`.pw`, `.cc`, `.info`)

3. **DNS Dinâmico Gratuito**
   - Detecta serviços como `no-ip`, `dyndns`, `ddns`, `dynu`
   - Comum em phishing por serem gratuitos e temporários

4. **Padrões Suspeitos**
   - URLs muito longas (>75 ou >100 caracteres)
   - Símbolo `@` na URL (técnica de obscurecimento)
   - Múltiplos hífens no domínio
   - Números suspeitos (ex: `paypa1`, `g00gle`)
   - Uso de IP ao invés de domínio
   - Portas não-padrão (diferente de 80/443)
   - Muitos subdomínios (ex: `a.b.c.d.site.com`)

5. **Palavras-Chave Suspeitas**
   - Detecta: `login`, `verify`, `secure`, `account`, `urgent`, `blocked`, etc.
   - Combinações de marca + palavra suspeita (ex: `paypal-secure-login`)

6. **Ausência de HTTPS**
   - Penaliza sites não-confiáveis que não usam HTTPS
   - Sites legítimos sempre usam criptografia

7. **Bases de Phishing Verificadas (CONCEITO C)**
   - **PhishTank**: Base com 15.000+ URLs verificadas (atualização a cada 4h)
   - **OpenPhish**: Feed em tempo real com 300+ URLs mais recentes
   - Sistema de cache inteligente para evitar rate limiting

8. **Análise de Domínio (CONCEITO B)**
   - **Idade do domínio** via WHOIS (domínios novos são suspeitos)
   - **Registros DNS** (múltiplos IPs podem indicar instabilidade)
   - **Certificado SSL/TLS** (autoassinados ou expirados = risco)

9. **Análise de Conteúdo Segura (CONCEITO B)**
   - Redirecionamentos múltiplos ou suspeitos
   - Formulários solicitando senhas
   - Campos sensíveis (cartão de crédito, CVV)
   - Uso de logos de marcas em domínios não-legítimos
   - **Nota**: Análise de conteúdo só em URLs com score inicial < 70

### 📊 Sistema de Scoring
- **Score 0-100**: Quanto maior, mais suspeito
- **Níveis de Risco**:
  - 🟢 **Low (0-24)**: Aparenta ser seguro
  - 🟡 **Medium (25-49)**: Suspeito
  - 🟠 **High (50-74)**: Provável phishing
  - 🔴 **Critical (75-100)**: Perigo crítico

### 🎨 Interface Moderna
- Design hacker/cyberpunk (preto e verde neon)
- Dashboard interativo em tempo real
- Gráfico de distribuição de riscos (Chart.js)
- Estatísticas de uso
- Histórico de análises

---

## 🚀 Instalação

### Pré-requisitos
- Python 3.8+
- pip

### Passo 1: Clone o repositório
```bash
git clone https://github.com/seu-usuario/WebPhisingTool.git
cd WebPhisingTool
```

### Passo 2: Crie um ambiente virtual (recomendado)
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### Passo 3: Instale as dependências
```bash
pip install -r requirements.txt
```

### Passo 4: Execute o servidor
```bash
cd src
python app.py
```

### Passo 5: Acesse o dashboard
Abra seu navegador em: **http://localhost:5000**

---

## 📖 Como Usar

### Interface Web (Dashboard)

1. Acesse `http://localhost:5000`
2. Digite a URL que deseja analisar
3. Clique em "Analisar Agora"
4. Veja o resultado com score de risco e fatores detectados

### API REST

#### 1. Analisar uma URL
```bash
POST /api/analyze
Content-Type: application/json

{
  "url": "http://paypa1-secure-login.no-ip.com"
}
```

**Resposta:**
```json
{
  "url": "http://paypa1-secure-login.no-ip.com",
  "domain": "paypa1-secure-login.no-ip.com",
  "risk_score": 95,
  "risk_level": "critical",
  "is_phishing": true,
  "features": {
    "url_length": 40,
    "uses_https": false,
    "numbers_in_domain": 1,
    "levenshtein_distance": 1,
    "closest_legitimate_domain": "paypal.com"
  },
  "risk_factors": [
    {
      "factor": "Typosquatting CRÍTICO",
      "severity": "critical",
      "score": 50,
      "detail": "Muito similar a 'paypal.com' (distância: 1)"
    },
    {
      "factor": "DNS dinâmico gratuito",
      "severity": "high",
      "score": 30,
      "detail": "Usa no-ip - comum em phishing"
    },
    {
      "factor": "Não usa HTTPS",
      "severity": "high",
      "score": 20,
      "detail": "Sites legítimos usam HTTPS"
    }
  ]
}
```

#### 2. Análise em lote
```bash
POST /api/batch
Content-Type: application/json

{
  "urls": [
    "https://google.com",
    "http://g00gle-login.tk",
    "https://github.com"
  ]
}
```

#### 3. Estatísticas
```bash
GET /api/statistics
```

#### 4. Histórico
```bash
GET /api/history?limit=10
```

#### 5. Health Check
```bash
GET /api/health
```

---

## 🧪 Testes

### Exemplos de URLs para Testar

#### ✅ URLs Legítimas (Score Baixo)
```
https://google.com
https://github.com
https://facebook.com
https://amazon.com
```

#### ⚠️ URLs Suspeitas (Score Médio/Alto)
```
http://login-verify-account.com
https://secure-banking-update.info
http://amazon-giftcard.tk
```

#### 🚨 URLs de Phishing (Score Crítico)
```
http://paypa1-secure-login.no-ip.com
http://g00gle.tk
http://192.168.1.1/login
http://micros0ft-verify@phishing.com
```

### Consultar PhishTank
Para URLs reais de phishing, consulte: [PhishTank](https://phishtank.org/)

---

## 🏆 Critérios de Avaliação Atendidos

### ✅ Conceito D
- [x] Interface web funcional
- [x] Análise básica de URLs

### ✅ Conceito C
- [x] API REST com múltiplos endpoints
- [x] Sistema de scoring (0-100)
- [x] Classificação de níveis de risco
- [x] **Integração com PhishTank** - Base de phishing verificada (cache 4h)
- [x] **Integração com OpenPhish** - Feed em tempo real

### ✅ Conceito B
- [x] **Análise heurística avançada** (20+ heurísticas):
  - Detecção de typosquatting (Levenshtein)
  - Identificação de TLDs de alto risco
  - Detecção de DNS dinâmico
  - Análise de estrutura da URL
  - Palavras-chave suspeitas
  - Verificação de HTTPS
  - Detecção de uso de IP
  - Padrões de marca + palavras suspeitas
- [x] **Bases de phishing externas**:
  - PhishTank (atualização a cada 4h)
  - OpenPhish (consulta em tempo real)
- [x] **Análise de domínio**:
  - Idade do domínio (WHOIS)
  - Registros DNS
  - Certificado SSL/TLS
- [x] **Análise de conteúdo** (quando seguro):
  - Detecção de redirecionamentos
  - Formulários de login
  - Campos sensíveis (senha, cartão)
  - Logos de marcas conhecidas
- [x] **Dashboard interativo** com gráficos (Chart.js)
- [x] **Estatísticas** em tempo real
- [x] **Design profissional** (tema hacker/cyberpunk)
- [x] **Sistema de cache inteligente** (evita rate limiting)

---

## 🛠️ Tecnologias Utilizadas

- **Backend**: Python 3.11, Flask 3.0.0
- **Frontend**: JavaScript, HTML5, CSS3
- **Bibliotecas Python**:
  - `python-Levenshtein` - Detecção de typosquatting
  - `Flask-CORS` - Suporte a requisições cross-origin
  - `python-whois` - Consulta idade de domínios
  - `dnspython` - Análise de registros DNS
  - `requests` - Integração com APIs externas
  - `beautifulsoup4` - Análise de conteúdo HTML
- **APIs Externas**:
  - PhishTank - Base de URLs de phishing verificadas
  - OpenPhish - Feed em tempo real
- **Frontend**:
  - Chart.js - Visualização de dados
  - Axios - Requisições HTTP
- **Fontes**: Orbitron, Roboto Mono (Google Fonts)

---

## 📁 Estrutura do Projeto

```
WebPhisingTool/
├── src/
│   ├── app.py                 # API Flask
│   ├── scanner.py             # Motor de análise heurística (20+ heurísticas)
│   └── templates/
│       └── index.html         # Dashboard interativo
├── phishtank_cache.json       # Cache local do PhishTank (4h)
├── requirements.txt           # Dependências Python
└── README.md                  # Este arquivo
```

---

## 🔒 Segurança

### Sistema Híbrido de Análise

**PhishBuster** usa uma abordagem híbrida inteligente:

1. **Análise Heurística (Fase 1)** - 100% Segura
   - Analisa apenas a **estrutura da URL** (texto)
   - Nenhum acesso ao site é feito
   - Score inicial calculado

2. **Consulta a Bases Externas (Fase 2)**
   - PhishTank: cache local atualizado a cada 4h
   - OpenPhish: feed em tempo real
   - **Se encontrado = PHISHING CONFIRMADO (score +60)**

3. **Análise Avançada (Fase 3)** - Apenas se Score < 70
   - Se URL parece legítima (score baixo), fazemos:
     - Consulta WHOIS (idade do domínio)
     - Verificação DNS
     - Validação de certificado SSL
     - Análise de redirecionamentos
     - Inspeção de conteúdo HTML
   - **URLs muito suspeitas NÃO são acessadas!**

### Por que esse modelo é seguro?

✅ **URLs perigosas nunca são acessadas** (score inicial alto)  
✅ **Apenas sites aparentemente legítimos** passam pela análise avançada  
✅ **Bases de phishing verificadas** detectam ameaças conhecidas  
✅ **Cache local** reduz dependência de APIs externas

### Proteção contra:

- 🛡️ Malware e scripts maliciosos
- 🛡️ Rastreamento pelo atacante
- 🛡️ Contaminação do sistema
- 🛡️ Rate limiting de APIs (cache inteligente)

---

## 🎓 TecHack - Insper 2025.2

**Autor**: [Seu Nome]  
**Instituição**: Insper  
**Disciplina**: Segurança da Informação  
**Conceito Alvo**: B

### Diferenciais do Projeto

1. ✅ **Segurança híbrida inteligente** - Não acessa URLs muito suspeitas
2. ✅ **Integração com 2 bases de phishing** (PhishTank + OpenPhish)
3. ✅ **Sistema de cache inteligente** (4h) para evitar rate limiting
4. ✅ **20+ heurísticas trabalhando em conjunto**
5. ✅ **Typosquatting detection** com algoritmo de Levenshtein
6. ✅ **Análise de domínio completa** (WHOIS, DNS, SSL)
7. ✅ **Análise de conteúdo** (formulários, redirecionamentos)
8. ✅ **Interface moderna** estilo cyberpunk
9. ✅ **Sistema de scoring robusto** com justificativa de cada ponto
10. ✅ **API REST completa** para integração

---

## 📊 Exemplos de Detecção

### Caso 1: Phishing Confirmado (PhishTank)
```
URL: http://cpanelweb2039.weebly.com/sbn3xcyf/hC2dZi/
Score: 135/100 (Very Critical)
Fatores:
- 🚨 CONFIRMADO no PhishTank [+60]
- Path com caracteres aleatórios [+25]
- Domínio com números aleatórios [+25]
- Palavras suspeitas [+10]
- Não usa HTTPS [+20]
```

### Caso 2: Typosquatting
```
URL: http://paypa1-secure.com
Score: 80/100 (Critical)
Fatores:
- Typosquatting: Similar a "paypal.com" (distância: 1) [+50]
- Palavra suspeita: "secure" [+10]
- Não usa HTTPS [+20]
```

### Caso 3: DNS Dinâmico
```
URL: http://login-verify.no-ip.org
Score: 70/100 (High)
Fatores:
- DNS dinâmico gratuito: no-ip [+30]
- Múltiplas palavras suspeitas [+20]
- Não usa HTTPS [+20]
```

### Caso 4: URL Legítima
```
URL: https://github.com
Score: 0/100 (Low)
Fatores: Nenhum fator de risco detectado
```

---

## 🚀 Próximas Melhorias (Para Conceito A+)

- ✨ Machine Learning para classificação automática
- ✨ Integração com VirusTotal API
- ✨ Sistema de reputação histórica de domínios
- ✨ Exportação de relatórios (PDF, CSV)
- ✨ Notificações em tempo real
- ✨ API key própria do PhishTank (acesso ilimitado)

---

## 📝 Licença

Este projeto foi desenvolvido para fins educacionais como parte do TecHack 2025.2 do Insper.

---

## 🤝 Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests.

---