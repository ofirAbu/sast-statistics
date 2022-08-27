import pandas as pd
import streamlit as st
import plotly.graph_objects as go

codeql_df = pd.read_html('https://codeql.github.com/codeql-query-help/full-cwe/')[0]
cwe_df = pd.read_csv('./cwe_vulnerabilities.csv', index_col=False)
codeql_df["CWE"] = codeql_df["CWE"].apply(
    lambda cwe: f"{cwe}: {cwe_df[cwe_df['CWE-ID'] == int(cwe[4:])]['Name'].values}")

languages = codeql_df['Language'].unique().tolist()

st.title("CodeQL Analyzer")
language = st.selectbox("Select Language to Analyze", languages)

vulnerabilities_list = codeql_df[codeql_df["Language"] == language]["CWE"].tolist()
fig = go.Figure()
fig.add_trace(go.Histogram(x=vulnerabilities_list))
fig.update_layout(title=f'{language}-CWE vulnerabilities')

st.plotly_chart(fig)
