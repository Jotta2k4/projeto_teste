# TENTATIVA 1
# import requests
# import json
#
# SITE = "https://eu2.wpsandbox.org/site/s-qn6lvxta4wc6l"
# COMMON_PLUGINS = ["duplicator", "wp-file-manager", "wp-maintenance"]
#
# # Carregar base de dados de vulnerabilidades
# with open("vulnerabilidades.json") as f:
#     VULNERABILIDADES = json.load(f)
#
# def plugin_existe(plugin):
#     url = f"{SITE}/wp-content/plugins/{plugin}/"
#     try:
#         r = requests.get(url, timeout=5)
#         return r.status_code == 200
#     except requests.exceptions.RequestException:
#         return False
#
# def obter_versao_plugin(plugin):
#     url = f"{SITE}/wp-content/plugins/{plugin}/readme.txt"
#     try:
#         r = requests.get(url, timeout=5)
#         if "Stable tag:" in r.text:
#             for line in r.text.splitlines():
#                 if "Stable tag:" in line:
#                     return line.split(":")[1].strip()
#     except:
#         return None
#
# def verificar_vulnerabilidade(plugin, versao):
#     if plugin in VULNERABILIDADES:
#         if versao in VULNERABILIDADES[plugin]:
#             return True
#     return False
#
# def main():
#     print(f"\n[+] Escaneando plugins no site {SITE}...\n")
#     for plugin in COMMON_PLUGINS:
#         if plugin_existe(plugin):
#             print(f"🔍 Plugin detectado: {plugin}")
#             versao = obter_versao_plugin(plugin)
#             if versao:
#                 print(f"    ➤ Versão: {versao}")
#                 if verificar_vulnerabilidade(plugin, versao):
#                     print(f"    ⚠️  VULNERABILIDADE DETECTADA!")
#                 else:
#                     print("    ✅ Sem vulnerabilidade conhecida nessa versão.")
#             else:
#                 print("    ⚠️  Não foi possível identificar a versão.")
#         else:
#             print(f"❌ Plugin ausente: {plugin}")
#     print("\n[✓] Escaneamento finalizado.")
#
#
# if __name__ == "__main__":
#     main()


# TENTATIVA 2
# import requests
# from bs4 import BeautifulSoup
#
# # URL base do seu site
# SITE = "https://eu2.wpsandbox.org/site/s-qn6lvxta4wc6l/teste-wp-p6"
# PLUGIN = "duplicator"
#
#
# # Tenta ler arquivos como readme.txt, changelog.txt, plugin.php
# def tentar_versao_em_arquivos(plugin):
#     caminhos = ["readme.txt", "changelog.txt", "plugin.php"]
#     for arquivo in caminhos:
#         url = f"{SITE}/wp-content/plugins/{plugin}/{arquivo}"
#         try:
#             r = requests.get(url, timeout=5)
#             if r.status_code == 200:
#                 texto = r.text.lower()
#                 if "version" in texto or "stable tag" in texto:
#                     for linha in texto.splitlines():
#                         if "version" in linha or "stable tag" in linha:
#                             return f"[ARQUIVO] {arquivo} → {linha.strip()}"
#         except:
#             continue
#     return None
#
#
# # Tenta extrair versão do HTML (ex: ver=1.2.3 em CSS/JS)
# def extrair_versao_do_html(plugin):
#     try:
#         r = requests.get(SITE, timeout=5)
#         soup = BeautifulSoup(r.text, "html.parser")
#         for tag in soup.find_all(["link", "script"]):
#             attr = tag.get("href") or tag.get("src")
#             if attr and f"/wp-content/plugins/{plugin}/" in attr and "ver=" in attr:
#                 versao = attr.split("ver=")[-1]
#                 return f"[HTML] Encontrado parâmetro ver= → {versao}"
#     except:
#         return None
#     return None
#
#
# # Execução
# if __name__ == "__main__":
#     print("🔍 Buscando versão do plugin:", PLUGIN)
#
#     resultado_arquivos = tentar_versao_em_arquivos(PLUGIN)
#     resultado_html = extrair_versao_do_html(PLUGIN)
#
#     if resultado_arquivos:
#         print("✅ Versão detectada via arquivos:", resultado_arquivos)
#     else:
#         print("❌ Não foi possível detectar via arquivos")
#
#     if resultado_html:
#         print("✅ Versão detectada via HTML:", resultado_html)
#     else:
#         print("❌ Não foi possível detectar via HTML")
#
#     if not resultado_arquivos and not resultado_html:
#         print("⚠️ Tente expor ou liberar readme.txt no servidor para facilitar o reconhecimento.")


# TENTATIVA 3
import requests
import json
from datetime import datetime

# Configurações
WPVULNDB_API_URL = "https://wpscan.com/api/v3/plugins/"
WPVULNDB_API_TOKEN = "sv6ravJXyeoxviYzYCiKf3sMlG9ZBfT2s7qsGavgahY"


def check_plugin_vulnerabilities(plugin_name, plugin_version):
    #Verifica vulnerabilidades em um plugin WordPress
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
                # Verifica se a versão do plugin é afetada
                if 'fixed_in' not in vuln or vuln['fixed_in'] > plugin_version:
                    relevant_vulns.append(vuln)

            return relevant_vulns
        else:
            return None

    except requests.exceptions.RequestException as e:
        print(f"Erro ao acessar a API: {e}")
        return None


def generate_report(plugin_name, plugin_version, vulnerabilities):
    """Gera um relatório simples das vulnerabilidades encontradas"""
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

    # Lista de plugins para verificar (nome e versão)
    plugins_to_check = [
        # {"name": "akismet", "version": "4.1.7"},  # Exemplo - substitua pelos plugins que deseja verificar
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
