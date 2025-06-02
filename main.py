# TENTATIVA 3
import requests
import json
from datetime import datetime

# Configurações
WPVULNDB_API_URL = "https://wpscan.com/api/v3/plugins/"
WPVULNDB_API_TOKEN = "sv6ravJXyeoxviYzYCiKf3sMlG9ZBfT2s7qsGavgahY"


def check_plugin_vulnerabilities(plugin_name, plugin_version):
    headers = {
        'Authorization': f'Token token={WPVULNDB_API_TOKEN}',
        'User-Agent': 'WP Vuln Scanner/1.0'
    }

    try:
        response = requests.get(f"{WPVULNDB_API_URL}{plugin_name}", headers=headers)
        response.raise_for_status()

        data = response.json()

        if plugin_name in data:
            vulnerabilities = data[plugin_name].get('vulnerabilities', [])

            relevant_vulns = []
            for vuln in vulnerabilities:
                if 'fixed_in' not in vuln or vuln['fixed_in'] > plugin_version:
                    relevant_vulns.append(vuln)

            return relevant_vulns
        else:
            return None

    except requests.exceptions.RequestException as e:
        print(f"Erro ao acessar a API: {e}")
        return None


def generate_report(plugin_name, plugin_version, vulnerabilities):
    print("\n" + "=" * 50)
    print(f"Relatório de Segurança para o Plugin: {plugin_name} (versão {plugin_version})")
    print(f"Data da verificação: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    if not vulnerabilities:
        print("\n✅ Nenhuma vulnerabilidade conhecida encontrada para esta versão.")
        return

    print(f"\n⚠️ Foram encontradas {len(vulnerabilities)} vulnerabilidades:")

    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\nVulnerabilidade #{i}:")
        print(f"Título: {vuln.get('title', 'N/A')}")
        print(f"Tipo: {vuln.get('vuln_type', 'N/A')}")
        print(f"Classificação: {vuln.get('references', {}).get('cve', 'N/A')}")
        print(f"Versão corrigida: {vuln.get('fixed_in', 'N/A')}")
        print(f"Descrição: {vuln.get('description', 'N/A')}")

        if 'references' in vuln:
            print("\nReferências:")
            for ref_type, ref_url in vuln['references'].items():
                if ref_type != 'cve':
                    print(f"- {ref_type}: {ref_url}")


def main():
    print("Scanner de Vulnerabilidades em Plugins WordPress")
    print("=" * 50)

    plugins_to_check = [
        # {"name": "akismet", "version": "4.1.7"},
        # {"name": "woocommerce", "version": "5.5.2"},
        # {"name": "elementor", "version": "3.4.7"},
        {"name": "duplicator", "version": "1.3.28"}
    ]

    for plugin in plugins_to_check:
        plugin_name = plugin["name"]
        plugin_version = plugin["version"]

        print(f"\nVerificando {plugin_name} versão {plugin_version}...")

        vulnerabilities = check_plugin_vulnerabilities(plugin_name, plugin_version)

        if vulnerabilities is not None:
            generate_report(plugin_name, plugin_version, vulnerabilities)
        else:
            print(f"Não foi possível obter informações sobre {plugin_name}")


if __name__ == "__main__":
    main()
