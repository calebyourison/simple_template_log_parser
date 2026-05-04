from io import BytesIO, StringIO, TextIOBase
import pandas as pd

from template_workflows.templates.ubuntu import (
    ubuntu_templates,
    base_ubuntu_templates,
    base_debian_templates
)

from template_workflows.functions.merge import merge_events

from template_log_parser import compile_templates, process_log

ubuntu_merge_events_dict = {
    "ubuntu": [value[1] for value in ubuntu_templates],
    "debian": [value[1] for value in base_debian_templates],
}

def ubuntu_log(file: str | BytesIO | StringIO | TextIOBase) -> dict[str, pd.DataFrame]:
    """Workflow for Ubuntu log files"""
    templates = compile_templates(base_ubuntu_templates)

    base_output = process_log(file=file, templates=templates, dict_format=False, datetime_columns=["time"])

    final_output = merge_events(base_output, ubuntu_merge_events_dict)

    return final_output
