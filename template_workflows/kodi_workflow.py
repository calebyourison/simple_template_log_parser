from io import BytesIO, StringIO, TextIOBase
import pandas as pd

from template_workflows.templates.kodi import (
    base_kodi_templates,
    error_templates,
    warning_templates,
    debug_templates,
    program_action_templates,
    general_templates,
    system_info_templates
)
from template_log_parser import compile_templates, process_log
from template_log_parser.log_functions import get_lines_from_file

from template_workflows.functions.merge import merge_events

kodi_merge_events_dict = {
    "program_action": [value[1] for value in program_action_templates],
    "general": [value[1] for value in general_templates],
    "system_info": [value[1] for value in system_info_templates],
    "debug": [value[1] for value in debug_templates],
    "error": [value[1] for value in error_templates],
    "warning": [value[1] for value in warning_templates],
}

eliminate_text = [
    "-----------------------------------------------------------------------"
]


def join_whitespace_lines(lines:list[str]) -> list[str]:
    """Lines beginning with whitespace to be associated with preceding line(s)"""
    joined_lines = []

    index = 0
    while index < len(lines):
        line = lines[index]

        # Normal line, no whitespace
        if not line.startswith("  "):

            combined = [line.strip()]

            # continued whitespace lines
            continued_index = index + 1
            while continued_index < len(lines) and lines[continued_index].startswith("  "):
                combined.append(lines[continued_index].strip())
                continued_index += 1

            joined_lines.append(" ".join(combined))
            index = continued_index

        else:
            index += 1

    return joined_lines


def link_devices(lines: list[str]) -> list[str]:
    """Links lines associated with devices"""

    output = []

    delimiter = ">: "
    current_index = 0
    total_lines = len(lines)
    while current_index < total_lines:
        line = lines[current_index]

        if delimiter not in line:
            output.append(line)
            current_index += 1
            continue

        _, content = line.split(delimiter, 1)

        # Device line handling
        if "  Device" in content:
            combined = [line.strip()]
            linked_index = current_index + 1

            while (
                    linked_index < total_lines
                    and "m_" in lines[linked_index]
            ):
                _, linked_content = lines[linked_index].split(delimiter, 1)

                # Normalize whitespace
                linked_content = " ".join(linked_content.split())

                combined.append(linked_content.strip())
                linked_index += 1

            output.append(" ".join(combined))
            current_index = linked_index
        else:
            output.append(line)
            current_index += 1

    return output

def kodi_log(file: str | BytesIO | StringIO | TextIOBase, split_text:str=None) -> dict[str, pd.DataFrame]:
    """Workflow for Kodi log files"""
    lines = get_lines_from_file(file)
    if split_text:
        lines = [line.split(split_text, 1)[1] for line in lines if split_text in line]

    joined_lines = join_whitespace_lines(lines)

    linked_devices = link_devices(joined_lines)

    string = StringIO("\n".join(linked_devices))

    templates = compile_templates(base_kodi_templates)

    base_output = process_log(file=string, templates=templates, dict_format=False, eliminate=eliminate_text)

    final_output = merge_events(base_output, kodi_merge_events_dict)

    return final_output
