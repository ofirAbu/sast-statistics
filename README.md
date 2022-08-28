# Sast Analyzer

A project for:
1. Analyzing the Semgrep rules wrt the OWASP and CWE vulnerabilities.
2. Analyzing the *CodeQL* rules wrt the OWASP and CWE vulnerabilities.
3. Analyzing *CodeQL* `.dbscheme` file, printing all tables related to DATAFLOW.

*all tested with python3.7*.

### How to Run
1. ``pip install -r requirements.txt``
1. ``python ./clone_semgrep.py``
2. ``streamlit run streamlit_app.py``

#### CodeQL *dbscheme* analyzer:
1. Simply run the file at `./codeql_dbscheme_analyzer_main.py/codeql_dbscheme_analyzer_main.py.py`.

