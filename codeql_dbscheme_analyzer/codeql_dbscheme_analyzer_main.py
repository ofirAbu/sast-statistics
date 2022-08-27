from functools import reduce
from typing import Tuple, List

DATAFLOW_EXTENDED_TYPES = ['@expr', '@function_decl_stmt', '@class_decl_stmt', '@namespace_declaration',
                           '@enum_declaration', '@property', '@dataflownode']


def get_all_table_definitions_line_numbers() -> Tuple[List[Tuple[int, int]], List[str]]:
    with open('./semmlecode.javascript.dbscheme') as f_handle:
        dbscheme_lines = f_handle.readlines()

    current_tuple_in_process: List[int] = []
    line_indices: List[Tuple[int, int]] = []
    for i, line in enumerate(dbscheme_lines):
        if '(' in line and len(current_tuple_in_process) == 0:
            current_tuple_in_process.append(i)
        if ');' in line and len(current_tuple_in_process) == 1:
            current_tuple_in_process.append(i)
        if len(current_tuple_in_process) == 2:
            line_indices.append((current_tuple_in_process[0], current_tuple_in_process[1]))
            current_tuple_in_process = []

    return line_indices, dbscheme_lines


def get_table_name_from_line(line: str) -> str:
    return line.split('(')[0]


def get_all_dataflow_codeql_tables(get_only_table_name: bool = True) -> List[str]:
    tables_names: List[str] = []
    tables_definitions_lines, tables_definitions_text = get_all_table_definitions_line_numbers()
    for table_definition_start, table_definition_end in tables_definitions_lines:
        table_definition = reduce(lambda str1, str2: str1 + str2,
                                  tables_definitions_text[table_definition_start: table_definition_end + 1])
        for dataflow_type in DATAFLOW_EXTENDED_TYPES:
            if dataflow_type in table_definition:
                tables_names.append(get_table_name_from_line(
                    tables_definitions_text[table_definition_start]) if get_only_table_name else table_definition)
                break

    return tables_names


if __name__ == '__main__':
    print(f"all table names involving dataflow nodes:\n{get_all_dataflow_codeql_tables()}")
    print("All table definitions involving dataflow nodes\n=======")

    dataflow_table_definitions = get_all_dataflow_codeql_tables(get_only_table_name=False)
    for dataflow_table_definition in dataflow_table_definitions:
        print(f"{dataflow_table_definition}\n=======")
