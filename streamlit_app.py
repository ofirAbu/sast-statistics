import streamlit as st

from analyzer import get_languages_to_paths_dictionary, get_plotly_histogram

languages = get_languages_to_paths_dictionary()

st.title("Semgrep Analyzer")
language = st.selectbox("Select Language to Analyze", list(languages.keys()))

vulnerability_hist_owasp = get_plotly_histogram(language_path=languages[language],
                                          vulnerability_classifier='owasp')
vulnerability_hist_cwe = get_plotly_histogram(language_path=languages[language],
                                          vulnerability_classifier='cwe')

st.plotly_chart(vulnerability_hist_owasp)
st.plotly_chart(vulnerability_hist_cwe)
