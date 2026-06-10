import re
import urllib.parse

import streamlit as st

st.set_page_config(
    page_title="Cyber URL Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
body {
    background-color: #050816;
    color: #e9f1ff;
}
section.main {
    background: rgba(10, 18, 43, 0.95);
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #071023 0%, #0e1b3b 100%);
    color: #c8d1ff;
}
.stButton>button {
    background: #1f3b8a;
    color: #f7fcff;
    border-radius: 999px;
    border: 1px solid #2a57b0;
}
.stButton>button:hover {
    background: #2d4fbb;
}
.stTextInput>div>div>input {
    background: #0f1a35;
    color: #eef4ff;
    border: 1px solid #2855c5;
}
.stTextArea>div>div>textarea {
    background: #0f1a35;
    color: #eef4ff;
    border: 1px solid #2855c5;
}
.reportview-container .markdown-text-container h1,
.reportview-container .markdown-text-container h2,
.reportview-container .markdown-text-container h3 {
    color: #f1f7ff;
}
.css-1d391kg {
    background: rgba(14, 24, 55, 0.88);
    border-radius: 24px;
    box-shadow: 0 16px 60px rgba(0, 0, 0, 0.45);
}
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

st.markdown(
    "# 🛡️ Cyber URL Sentinel"
)
st.markdown(
    "### Verifique rapidamente se URLs parecem suspeitas ou maliciosas com análises inspiradas em segurança cibernética."
)

with st.expander("Como funciona", expanded=True):
    st.write(
        "O detector aplica regras heurísticas em cada URL para identificar padrões comuns de phishing e ataques, como domínios longos, subdomínios suspeitos, IPs no hostname, TLDs estranhos e palavras-chave perigosas."
    )

with st.sidebar:
    st.markdown("## 🔍 Ferramentas e dicas")
    st.markdown(
        "- Insira uma ou mais URLs, uma por linha.\n"
        "- O analisador calcula um score de risco e destaca os sinais de alerta principais.\n"
        "- Use este app para triagem rápida antes de abrir links desconhecidos."
    )
    st.markdown("---")
    st.markdown("## 🧠 Inspiração")
    st.markdown(
        "Interface inspirada em painéis de segurança e operações cibernéticas, com cores frias, realces neons e foco em clareza visual."
    )

URL_HINT = "https://exemplo.com/login?session=abc"
urls_input = st.text_area(
    "Cole aqui a URL ou várias URLs (uma por linha)",
    placeholder=URL_HINT,
    height=160,
)

danger_keywords = [
    "login", "secure", "verify", "account", "update", "confirm", "reset", "bank", "paypal", "ebay", "amazon",
    "secure", "verify", "confirm", "signin",
]

ip_pattern = re.compile(
    r"^(?:http[s]?://)?(?:\[?\d{1,3}(?:\.\d{1,3}){3}\]?|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:/|$)")

suspicious_tlds = {
    "top", "xyz", "zip", "review", "country", "kim", "loan", "win", "live", "trade",
}

punycode_pattern = re.compile(r"xn--")
hex_pattern = re.compile(r"%[0-9A-Fa-f]{2}")


def analyze_url(url: str) -> dict:
    original = url.strip()
    if not original:
        return {}

    if not re.match(r"^https?://", original, re.IGNORECASE):
        normalized = "http://" + original
    else:
        normalized = original

    parsed = urllib.parse.urlparse(normalized)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    findings = []
    score = 0

    if parsed.scheme != "https":
        findings.append("Conexão não segura (não HTTPS)")
        score += 20

    if ip_pattern.match(original):
        findings.append("URL usa endereço IP em vez de domínio")
        score += 25

    if hostname.count('.') >= 4:
        findings.append("Muitos subdomínios ou domínio extenso")
        score += 15

    if len(original) > 80:
        findings.append("URL muito longa")
        score += 15

    if punycode_pattern.search(hostname):
        findings.append("Punycode detectado, possível homógrafo")
        score += 30

    if '@' in original:
        findings.append("Símbolo '@' presente na URL")
        score += 30

    if hex_pattern.search(original) and len(query) > 0:
        findings.append("Codificação hex (%) presente em parâmetros")
        score += 10

    if any(keyword in original.lower() for keyword in danger_keywords):
        findings.append("Palavras de phishing encontradas na URL")
        score += 15

    if hostname.split('.')[-1] in suspicious_tlds:
        findings.append("TLD incomum ou potencialmente arriscado")
        score += 15

    if len(path) > 40:
        findings.append("Caminho da URL muito longo")
        score += 10

    if query and any(param in query.lower() for param in ["token=", "session=", "auth=", "password=", "passwd="]):
        findings.append("Parâmetros sensíveis na query string")
        score += 20

    if hostname.startswith("www.") and len(hostname.split('.')) >= 4:
        findings.append(
            "Subdomínios encadeados podem esconder domínio verdadeiro")
        score += 10

    if not hostname or hostname == "":
        findings.append("Hostname inválido ou ausente")
        score += 40

    score = min(score, 100)
    risk = "Baixo"
    if score >= 70:
        risk = "Alto"
    elif score >= 40:
        risk = "Médio"

    return {
        "original": original,
        "normalized": normalized,
        "hostname": hostname,
        "path": path,
        "query": query,
        "score": score,
        "risk": risk,
        "findings": findings or ["Nenhum sinal de risco imediato detectado."],
    }


if st.button("Analisar URL"):
    urls = [line for line in urls_input.splitlines() if line.strip()]
    if not urls:
        st.warning("Por favor, insira ao menos uma URL para análise.")
    else:
        results = [analyze_url(url) for url in urls]

        for result in results:
            if not result:
                continue

            if result["score"] >= 70:
                color = "#ff4d4d"
            elif result["score"] >= 40:
                color = "#f6c23e"
            else:
                color = "#4cd137"

            st.markdown(
                f"<div style='border:1px solid {color}; border-radius:20px; padding:18px; margin-bottom:18px; background:rgba(12,23,45,0.88);'>"
                f"<h3 style='margin-bottom:8px;'>🔗 {result['original']}</h3>"
                f"<p style='margin:0 0 12px 0; color:#b8c6ff;'>Risco estimado: "
                f"<span style='font-weight:700; color:{color};'>{result['risk']} ({result['score']}%)</span></p>"
                f"<p style='margin:0 0 4px 0;'>Host: <strong>{result['hostname']}</strong></p>"
                f"<p style='margin:0 0 12px 0;'>Caminho: <strong>{result['path'] or '/'}</strong></p>"
                f"<p style='margin:0 0 12px 0;'>Query: <strong>{result['query'] or 'nenhuma'}</strong></p>"
                f"<ul style='margin:0 0 0 18px; padding:0;'>"
                + ''.join(f"<li style='margin-bottom:6px;color:#d0d9ff;'>{finding}</li>" for finding in result['findings'])
                + "</ul></div>",
                unsafe_allow_html=True,
            )

        st.markdown("---")
        st.subheader("Sugestões de segurança")
        st.markdown(
            "- Nunca abra links recebidos por mensagens não solicitadas sem verificar a fonte.\n"
            "- Prefira digitar o domínio diretamente no navegador em vez de clicar em links suspeitos.\n"
            "- Verifique se o site usa HTTPS e se o certificado é válido.\n"
            "- Em caso de dúvida, use ferramentas de análise de URL ou serviços de reputação de domínio."
        )

        if any(result["score"] >= 70 for result in results):
            st.error(
                "⚠️ Atenção: uma ou mais URLs apresentaram alto risco. Evite acessá-las sem verificação adicional.")
        elif any(result["score"] >= 40 for result in results):
            st.warning(
                "⚠️ Atenção: algumas URLs apresentam risco moderado. Revise com cautela.")
        else:
            st.success(
                "✅ Todas as URLs analisadas parecem ter baixo risco à primeira vista.")
