from functools import reduce

import pandas as pd
import streamlit as st
import plotly.graph_objects as go

from semgrep_analyzer import get_languages_to_paths_dictionary, get_plotly_histogram, \
    get_vulnerabilities_list_of_language

semgrep_languages = get_languages_to_paths_dictionary()
codeql_df = pd.read_html('https://codeql.github.com/codeql-query-help/full-cwe/')[0]
cwe_df = pd.read_csv('./cwe_vulnerabilities.csv', index_col=False)
codeql_df["CWE"] = codeql_df["CWE"].apply(
    lambda cwe: f"{cwe}: {cwe_df[cwe_df['CWE-ID'] == int(cwe[4:])]['Name'].values}")
codeql_languages = codeql_df['Language'].unique().tolist()

st.title("SAST Analyzer")
sast_product = st.selectbox("Select sast product to analyze", ["semgrep", "codeql", "both"])
if sast_product == 'semgrep':
    language = st.selectbox("Select Language to Analyze", list(semgrep_languages.keys()))

    vulnerability_hist_owasp = get_plotly_histogram(language_path=semgrep_languages[language],
                                                    vulnerability_classifier='owasp')
    vulnerability_hist_cwe = get_plotly_histogram(language_path=semgrep_languages[language],
                                                  vulnerability_classifier='cwe')

    st.plotly_chart(vulnerability_hist_owasp)
    st.plotly_chart(vulnerability_hist_cwe)

elif sast_product == 'codeql':
    language = st.selectbox("Select Language to Analyze", codeql_languages)

    vulnerabilities_list = codeql_df[codeql_df["Language"] == language]["CWE"].tolist()
    fig = go.Figure()
    fig.add_trace(go.Histogram(x=vulnerabilities_list))
    fig.update_xaxes(tickangle=45)
    fig.update_layout(title=f'{language}-CWE vulnerabilities', width=1000, height=1000)

    st.plotly_chart(fig)

elif sast_product == 'both':
    codeql_df["Language"] = codeql_df["Language"].apply(lambda lang: "javascript" if lang == "typescript" else (
        "csharp" if lang == "C#" else lang.replace("+", "").lower()))
    codeql_languages = codeql_df['Language'].unique().tolist()
    intersected_languages = list(set(codeql_languages).intersection(semgrep_languages))
    language = st.selectbox("Select Language to Analyze", intersected_languages)
    semgrep_vulnerabilities = get_vulnerabilities_list_of_language(language_path=semgrep_languages[language],
                                                                   class_type="cwe")
    semgrep_vulnerabilities = [
        f"{cwe.split(':')[0]}: {cwe_df[cwe_df['CWE-ID'] == int(cwe.split(':')[0].split('-')[-1])]['Name'].values}" for
        cwe in semgrep_vulnerabilities]
    codeql_vulnerabilities_list = codeql_df[codeql_df["Language"] == language]["CWE"].tolist()

    fig = go.Figure()
    codeql_vulnerabilities_list = [reduce(lambda str1, str2: str1 + ' ' + str2, vuln.split(': ')[-1].split()[:5]) for
                                   vuln in codeql_vulnerabilities_list]
    semgrep_vulnerabilities = [reduce(lambda str1, str2: str1 + ' ' + str2, vuln.split(': ')[-1].split()[:5]) for vuln
                               in semgrep_vulnerabilities]
    fig.add_trace(go.Histogram(name='codeql', x=codeql_vulnerabilities_list))
    fig.add_trace(go.Histogram(name='semgrep', x=semgrep_vulnerabilities))
    fig.update_xaxes(tickangle=45)
    fig.update_layout(title=f'{language}-CWE vulnerabilities', width=1000, height=1000)

    st.plotly_chart(fig)
