#!/usr/bin/env python3
"""
Script Keep-Alive para manter aplicação Streamlit acordada.

Faz ping periódico na aplicação para evitar que entre em modo sleep.
Executado automaticamente via GitHub Actions.
"""

import os
import sys
import requests
from datetime import datetime
import time

def ping_streamlit_app():
    """
    Faz ping na aplicação Streamlit para mantê-la ativa.
    """
    # Obter URL da aplicação (de variável de ambiente ou secret)
    app_url = os.environ.get('STREAMLIT_APP_URL')

    if not app_url:
        print("❌ ERRO: URL da aplicação não configurada!")
        print("Configure STREAMLIT_APP_URL nos GitHub Secrets")
        return False

    # Garantir que a URL termina sem barra
    app_url = app_url.rstrip('/')

    print(f"🔍 Iniciando keep-alive...")
    print(f"🌐 URL: {app_url}")
    print(f"⏰ Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    try:
        # Fazer requisição GET para manter app ativo
        print("📡 Enviando requisição...")

        response = requests.get(
            app_url,
            timeout=30,
            headers={
                'User-Agent': 'GitHub-Actions-KeepAlive/1.0',
                'Accept': 'text/html,application/xhtml+xml'
            }
        )

        print(f"✅ Status Code: {response.status_code}")
        print(f"⏱️  Tempo de resposta: {response.elapsed.total_seconds():.2f}s")

        if response.status_code == 200:
            print("✅ Aplicação está ATIVA e RESPONDENDO!")
            return True
        elif response.status_code in [301, 302, 307, 308]:
            print(f"⚠️  Redirecionamento detectado: {response.status_code}")
            print(f"📍 Location: {response.headers.get('Location', 'N/A')}")
            return True
        else:
            print(f"⚠️  Status inesperado: {response.status_code}")
            return False

    except requests.exceptions.Timeout:
        print("⏱️  TIMEOUT: Aplicação demorou muito para responder (>30s)")
        return False

    except requests.exceptions.ConnectionError as e:
        print(f"❌ ERRO DE CONEXÃO: {str(e)}")
        return False

    except Exception as e:
        print(f"❌ ERRO INESPERADO: {str(e)}")
        return False

    finally:
        print("-" * 60)
        print(f"🏁 Keep-alive finalizado em {datetime.now().strftime('%H:%M:%S')}")

def main():
    """Função principal."""
    print("=" * 60)
    print("🤖 KEEP-ALIVE BOT - Sistema Psi")
    print("=" * 60)
    print()

    sucesso = ping_streamlit_app()

    print()
    if sucesso:
        print("✅ Execução bem-sucedida!")
        sys.exit(0)
    else:
        print("❌ Execução com falhas!")
        sys.exit(1)

if __name__ == "__main__":
    main()
