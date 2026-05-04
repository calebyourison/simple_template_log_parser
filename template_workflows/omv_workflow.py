from io import BytesIO, StringIO, TextIOBase
import pandas as pd

from template_workflows.templates.omv import (
    base_omv_templates,
    omv_process_templates,
    openmediavault_process_templates,
    base_debian_templates,
    omv_other_templates
)
from template_workflows.functions.merge import merge_events

from template_log_parser import compile_templates, process_log

omv_merge_events_dict = {
    "omv": [value[1] for value in omv_process_templates],
    "openmediavault": [value[1] for value in openmediavault_process_templates],
    "omv_other": [value[1] for value in omv_other_templates],
    "debian": [value[1] for value in base_debian_templates]
}

def omv_log(file: str | BytesIO | StringIO | TextIOBase) -> dict[str, pd.DataFrame]:
    """Workflow for OMV log files"""
    templates = compile_templates(base_omv_templates)

    base_output = process_log(file=file, templates=templates, dict_format=False, datetime_columns=["time"])

    final_output = merge_events(base_output, omv_merge_events_dict)

    return final_output
