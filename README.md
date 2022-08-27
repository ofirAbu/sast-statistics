# Sast Analyzer

1. A project to help analyze the Semgrep rules wrt the OWASP and CWE vulnerabilities.
2. Analyzing *codeql* `.dbscheme` file, printing all tables related to DATAFLOW.

*all tested with python3.7*.

### How to Run
1. ``pip install -r requirements.txt``
   
#### Semgrep:
1. ``python ./clone_semgrep.py``
2. ``streamlit run streamlit_app.py``

#### CodeQL:
1. Simply run the file at `./codeql_analyzer/codeql_analyzer_main.py`.

