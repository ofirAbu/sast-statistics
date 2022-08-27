from os import listdir
from os.path import isdir, isfile
from pathlib import Path
from typing import List, Dict

import plotly
import plotly.graph_objects as go
import yaml


def get_all_languages_paths() -> List[Path]:
    only_dirs = [d for d in listdir('./semgrep/') if isdir(f'./semgrep/{d}') and not d.startswith('.')]

    return [Path(f'./semgrep/{d}').resolve() for d in only_dirs]


def get_all_security_related_yamls_from_dir_recursively(source_dir: Path, yamls: List[Path],
                                                        is_parent_security: bool) -> List[Path]:
    immediate_subdirs = [Path.resolve(Path(source_dir) / d) for d in listdir(source_dir) if isdir(Path(source_dir) / d)]
    for subdir in immediate_subdirs:
        yamls += get_all_security_related_yamls_from_dir_recursively(source_dir=subdir,
                                                                     yamls=yamls,
                                                                     is_parent_security=is_parent_security or
                                                                                        "security" in str(subdir))
    if is_parent_security:
        yamls += [Path.resolve(Path(source_dir) / f) for f in listdir(source_dir) if
                  isfile(Path(source_dir) / f) and f.endswith(".yaml")]

    return list(set(yamls))


def get_vulnerabilities_list_of_language(language_path: Path, class_type: str = 'owasp') -> List[str]:
    vuln_list = []
    yaml_files = get_all_security_related_yamls_from_dir_recursively(source_dir=language_path, yamls=[],
                                                                     is_parent_security=False)
    for yaml_file in yaml_files:
        with open(yaml_file, "r") as f_handle:
            yaml_dict = yaml.safe_load(f_handle)
        try:
            current_vuln = yaml_dict['rules'][0]['metadata'][class_type]
            vuln_list += current_vuln if isinstance(current_vuln, list) else [current_vuln]
        except Exception:
            pass

    return vuln_list


def get_languages_to_paths_dictionary() -> Dict[str, Path]:
    languages_paths = get_all_languages_paths()
    languages_to_paths_dictionary = {str(language_path).split("\\")[-1]: language_path for language_path in
                                     languages_paths}

    return languages_to_paths_dictionary


def get_plotly_histogram(language_path: Path, vulnerability_classifier: str = "owasp") -> plotly.graph_objects:
    language_title = str(language_path).split("\\")[-1]
    chart_title = f'{language_title}-{vulnerability_classifier.upper()} vulnerabilities'
    vulnerabilities_list = get_vulnerabilities_list_of_language(language_path, class_type=vulnerability_classifier)
    fig = go.Figure()
    fig.add_trace(go.Histogram(x=vulnerabilities_list))
    fig.update_layout(title=chart_title)

    return fig
