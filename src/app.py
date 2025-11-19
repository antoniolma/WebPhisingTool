"""
PhantomShield - Phishing Detection API (Conceito B)
API Flask para análise heurística de URLs
"""
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from scanner import PhishingScanner
from datetime import datetime
import json
import os

app = Flask(__name__)
CORS(app)

# Histórico de análises (em memória)
analysis_history = []
MAX_HISTORY = 100

# Estatísticas
stats = {
    'total_scans': 0,
    'phishing_detected': 0,
    'safe_urls': 0,
    'by_risk_level': {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
}


@app.route('/')
def index():
    """Dashboard principal"""
    return render_template('index.html')


@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'mode': 'safe_heuristic_only',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """
    Analisa uma URL para detectar phishing
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL é obrigatória'}), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({'error': 'URL não pode ser vazia'}), 400
        
        # Análise heurística (SEGURA - sem acessar a URL)
        scanner = PhishingScanner()
        result = scanner.analyze_url(url)
        
        # Atualiza estatísticas
        stats['total_scans'] += 1
        if result.get('is_phishing'):
            stats['phishing_detected'] += 1
        else:
            stats['safe_urls'] += 1
        
        risk_level = result.get('risk_level', 'unknown')
        if risk_level in stats['by_risk_level']:
            stats['by_risk_level'][risk_level] += 1
        
        # Adiciona ao histórico
        analysis_history.insert(0, {
            'url': url,
            'risk_score': result.get('risk_score', 0),
            'total_risk_score': result.get('total_risk_score', 0),
            'risk_level': risk_level,
            'is_phishing': result.get('is_phishing', False),
            'risk_factors': result.get('risk_factors', []),  # Adiciona fatores de risco
            'timestamp': result.get('timestamp')
        })
        
        # Limita tamanho do histórico
        if len(analysis_history) > MAX_HISTORY:
            analysis_history.pop()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/batch', methods=['POST'])
def batch_analyze():
    """
    Analisa múltiplas URLs de uma vez
    """
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({'error': 'Lista de URLs é obrigatória'}), 400
        
        urls = data['urls']
        
        if not isinstance(urls, list):
            return jsonify({'error': 'URLs deve ser uma lista'}), 400
        
        if len(urls) > 50:
            return jsonify({'error': 'Máximo de 50 URLs por vez'}), 400
        
        scanner = PhishingScanner()
        results = []
        
        for url in urls:
            if url and url.strip():
                result = scanner.analyze_url(url.strip())
                results.append(result)
                
                # Atualiza estatísticas
                stats['total_scans'] += 1
                if result.get('is_phishing'):
                    stats['phishing_detected'] += 1
                else:
                    stats['safe_urls'] += 1
                
                risk_level = result.get('risk_level', 'unknown')
                if risk_level in stats['by_risk_level']:
                    stats['by_risk_level'][risk_level] += 1
        
        return jsonify({
            'total': len(results),
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """
    Retorna estatísticas de uso
    """
    return jsonify(stats)


@app.route('/api/history', methods=['GET'])
def get_history():
    """
    Retorna histórico de análises com opção de exportação (CONCEITO B)
    """
    limit = request.args.get('limit', 10, type=int)
    export_format = request.args.get('format', None)  # json, csv, txt
    limit = min(limit, MAX_HISTORY)
    
    history_data = analysis_history[:limit]
    
    # Exportação em diferentes formatos
    if export_format == 'csv':
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['URL', 'Risk Score', 'Risk Level', 'Is Phishing', 'Timestamp'])
        
        for item in history_data:
            writer.writerow([
                item['url'],
                item['risk_score'],
                item['risk_level'],
                'Yes' if item['is_phishing'] else 'No',
                item['timestamp']
            ])
        
        return output.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename=phishing_history.csv'
        }
    
    elif export_format == 'txt':
        output = "=" * 70 + "\n"
        output += "PhishBuster - Histórico de Análises\n"
        output += "=" * 70 + "\n\n"
        
        for item in history_data:
            output += f"URL: {item['url']}\n"
            output += f"Score de Risco: {item['risk_score']}/100\n"
            output += f"Nível: {item['risk_level'].upper()}\n"
            output += f"Phishing: {'SIM' if item['is_phishing'] else 'NÃO'}\n"
            output += f"Data: {item['timestamp']}\n"
            output += "-" * 70 + "\n\n"
        
        return output, 200, {
            'Content-Type': 'text/plain',
            'Content-Disposition': 'attachment; filename=phishing_history.txt'
        }
    
    # JSON padrão
    return jsonify({
        'total': len(analysis_history),
        'history': history_data
    })



@app.route('/api/clear', methods=['POST'])
def clear_data():
    """
    Limpa histórico e estatísticas
    """
    global analysis_history, stats
    
    analysis_history = []
    stats = {
        'total_scans': 0,
        'phishing_detected': 0,
        'safe_urls': 0,
        'by_risk_level': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
    }
    
    return jsonify({'message': 'Dados limpos com sucesso'})


if __name__ == '__main__':
    print("=" * 70)
    print("🎯 PhishBuster - Phishing Detection Tool (Conceito B COMPLETO)")
    print("=" * 70)
    print("✅ CONCEITO C:")
    print("   • Verificação em bases de phishing")
    print("   • Detecção de números/caracteres suspeitos")
    print("   • Interface web com indicadores visuais")
    print()
    print("✅ CONCEITO B:")
    print("   • Análise de idade do domínio (WHOIS)")
    print("   • Verificação de DNS dinâmico")
    print("   • Análise de certificados SSL")
    print("   • Detecção de redirecionamentos")
    print("   • Distância de Levenshtein (typosquatting)")
    print("   • Análise de conteúdo (formulários/login)")
    print("   • Dashboard interativo com gráficos")
    print("   • Histórico com exportação (CSV/TXT)")
    print("=" * 70)
    print("🔒 Segurança: URLs com score inicial >70 NÃO são acessadas")
    print("📊 10+ heurísticas trabalhando em conjunto")
    print("=" * 70)
    print(f"🚀 Servidor rodando em http://localhost:5000")
    print("=" * 70)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
