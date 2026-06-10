# Projeto Final Kensei AI Foundations

Este repositório contém o projeto final da formação **Kensei AI Foundations**.

O aplicativo é um verificador de URLs suspeitas criado com **Streamlit**, com interface inspirada em temas de cibersegurança e operações de defesa digital.

## O que está incluído

- `app.py` — app principal em Streamlit
- `requirements.txt` — dependência necessária para rodar o app
- `RELATÓRIO FINAL - CYBER IA - KAROL FALCÃO.pdf` — relatório final do projeto

## Como executar

1. Instale as dependências:

```bash
pip install -r requirements.txt
```

2. Inicie o aplicativo:

```bash
streamlit run app.py
```

3. Abra o link exibido no terminal para acessar a interface.

## Sobre o projeto

O `Cyber URL Sentinel` analisa URLs em busca de sinais comuns de phishing e de risco, como:

- uso de IP em vez de domínio
- conexões não seguras (não HTTPS)
- domínios longos e subdomínios encadeados
- TLDs suspeitos
- presença de palavras comuns em URLs de phishing
- codificação oculta e parâmetros sensíveis

## Projetos das aulas anteriores

Confira os projetos desenvolvidos nas aulas anteriores da formação Kensei AI Foundations:

- [Kensei Cybersec AI](https://github.com/KFalcao/kensei-cybersec-ai/)

## Relatório do projeto

O relatório final do projeto está incluído no repositório como:

- `RELATÓRIO FINAL - CYBER IA - KAROL FALCÃO.pdf`
