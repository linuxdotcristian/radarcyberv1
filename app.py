
import streamlit as st
import requests
import time
import re

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={}"

def validate_cve_id(cve_id):
    """Valida se o formato do CVE ID está correto"""
    pattern = r'^CVE-\d{4}-\d{4,7}$'
    return bool(re.match(pattern, cve_id))

def fetch_cve_data(cve_id):
    cve_data = {
        "cvss_score": None,
        "is_in_kev": False,
        "epss_score": None,
        "description": "Descrição não encontrada.",
        "found": False
    }

    try:
        nvd_response = requests.get(NVD_API_URL.format(cve_id), timeout=10)
        nvd_response.raise_for_status()
        nvd_data = nvd_response.json()
        
        if "vulnerabilities" in nvd_data and len(nvd_data["vulnerabilities"]) > 0:
            cve_data["found"] = True
            cve_item = nvd_data["vulnerabilities"][0]["cve"]
            
            if "metrics" in cve_item and "cvssMetricV31" in cve_item["metrics"]:
                cvss_metric = cve_item["metrics"]["cvssMetricV31"][0]["cvssData"]
                cve_data["cvss_score"] = cvss_metric["baseScore"]
            elif "metrics" in cve_item and "cvssMetricV2" in cve_item["metrics"]:
                # Fallback para CVSS v2 se v3.1 não estiver disponível
                cvss_metric = cve_item["metrics"]["cvssMetricV2"][0]["cvssData"]
                cve_data["cvss_score"] = cvss_metric["baseScore"]
                
            if "descriptions" in cve_item:
                for desc in cve_item["descriptions"]:
                    if desc["lang"] == "en":
                        cve_data["description"] = desc["value"]
                        break
    except requests.exceptions.RequestException as e:
        st.error(f"Erro ao consultar NVD: {str(e)}")
    except (KeyError, IndexError) as e:
        st.error(f"Erro ao processar dados da NVD: {str(e)}")
    except Exception as e:
        st.error(f"Erro inesperado ao consultar NVD: {str(e)}")

    try:
        kev_response = requests.get(CISA_KEV_URL, timeout=10)
        kev_response.raise_for_status()
        kev_data = kev_response.json()
        for item in kev_data["vulnerabilities"]:
            if item["cveID"] == cve_id:
                cve_data["is_in_kev"] = True
                break
    except requests.exceptions.RequestException as e:
        st.warning(f"Erro ao consultar CISA KEV: {str(e)}")
    except (KeyError, IndexError) as e:
        st.warning(f"Erro ao processar dados do CISA KEV: {str(e)}")
    except Exception as e:
        st.warning(f"Erro inesperado ao consultar CISA KEV: {str(e)}")

    try:
        epss_response = requests.get(EPSS_API_URL.format(cve_id), timeout=10)
        epss_response.raise_for_status()
        epss_data = epss_response.json()
        if "data" in epss_data and len(epss_data["data"]) > 0:
            cve_data["epss_score"] = float(epss_data["data"][0]["epss"])
    except requests.exceptions.RequestException as e:
        st.warning(f"Erro ao consultar EPSS: {str(e)}")
    except (KeyError, IndexError, ValueError) as e:
        st.warning(f"Erro ao processar dados do EPSS: {str(e)}")
    except Exception as e:
        st.warning(f"Erro inesperado ao consultar EPSS: {str(e)}")

    time.sleep(1)
    return cve_data

def prioritize_cve(cve_data):
    if not cve_data["found"]:
        return "NÃO ENCONTRADO"
    if cve_data["is_in_kev"]:
        return "CRÍTICA"
    if cve_data["epss_score"] is not None and cve_data["epss_score"] >= 0.9:
        return "ALTA"
    if cve_data["cvss_score"] is not None and cve_data["cvss_score"] >= 7.0:
        return "MONITORAR"
    return "ADIAR"

# ---------------- INTERFACE ----------------
st.set_page_config(page_title="Radarcyber CVE Analyzer", layout="centered")
st.title("🛡 Radarcyber - Analisador de CVEs")

cve_id_input = st.text_input("Digite um ID de CVE (ex: CVE-2024-24919)").strip().upper()

if st.button("Analisar"):
    if not cve_id_input:
        st.error("Por favor, digite um ID de CVE válido.")
    elif not validate_cve_id(cve_id_input):
        st.error("Formato de CVE inválido. Use o formato: CVE-YYYY-NNNNN")
    else:
        with st.spinner("Consultando bases NVD, CISA e EPSS..."):
            cve_data = fetch_cve_data(cve_id_input)
            prioridade = prioritize_cve(cve_data)

        if cve_data["found"]:
            st.subheader(f"📌 Resumo para {cve_id_input}")
            st.write(f"**Descrição:** {cve_data['description']}")
            st.write(f"**Pontuação CVSS:** {cve_data['cvss_score'] if cve_data['cvss_score'] else 'N/A'}")
            st.write(f"**No Catálogo KEV:** {'✅ Sim' if cve_data['is_in_kev'] else '❌ Não'}")
            st.write(f"**Pontuação EPSS:** {cve_data['epss_score'] if cve_data['epss_score'] else 'N/A'}")
            st.markdown(f"### 🔎 Prioridade: **{prioridade}**")
        else:
            st.error(f"CVE {cve_id_input} não foi encontrado na base de dados NVD.")


