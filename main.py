import requests
import json

SITE = "https://eu2.wpsandbox.org/site/s-qbsh8m9mxlc6l/elementor-110"
COMMON_PLUGINS = ["duplicator", "wp-file-manager", "wp-maintenance"]

# Carregar base de dados de vulnerabilidades
with open("vulnerabilidades.json") as f:
    VULNERABILIDADES = json.load(f)

def plugin_existe(plugin):
    url = f"{SITE}/wp-content/plugins/{plugin}/"
    try:
        r = requests.get(url, timeout=5)
        return r.status_code == 200
    except requests.exceptions.RequestException:
        return False

def obter_versao_plugin(plugin):
    url = f"{SITE}/wp-content/plugins/{plugin}/readme.txt"
    try:
        r = requests.get(url, timeout=5)
        if "Stable tag:" in r.text:
            for line in r.text.splitlines():
                if "Stable tag:" in line:
                    return line.split(":")[1].strip()
    except:
        return None

def verificar_vulnerabilidade(plugin, versao):
    if plugin in VULNERABILIDADES:
        if versao in VULNERABILIDADES[plugin]:
            return True
    return False

def main():
    print(f"\n[+] Escaneando plugins no site {SITE}...\n")
    for plugin in COMMON_PLUGINS:
        if plugin_existe(plugin):
            print(f"🔍 Plugin detectado: {plugin}")
            versao = obter_versao_plugin(plugin)
            if versao:
                print(f"    ➤ Versão: {versao}")
                if verificar_vulnerabilidade(plugin, versao):
                    print(f"    ⚠️  VULNERABILIDADE DETECTADA!")
                else:
                    print("    ✅ Sem vulnerabilidade conhecida nessa versão.")
            else:
                print("    ⚠️  Não foi possível identificar a versão.")
        else:
            print(f"❌ Plugin ausente: {plugin}")
    print("\n[✓] Escaneamento finalizado.")


if __name__ == "__main__":
    main()
