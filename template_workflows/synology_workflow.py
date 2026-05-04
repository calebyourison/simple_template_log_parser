from io import BytesIO, StringIO, TextIOBase
import pandas as pd

from template_workflows.functions.column_functions import (
    calc_data_usage,
    isolate_ip_from_parentheses,
)

from template_workflows.templates.synology import (
    base_synology_templates,
    tasks_templates,
    general_system_templates,
    user_activity_templates,
)

synology_merge_events_dict = {
    "tasks": [value[1] for value in tasks_templates],
    "general_system": [value[1] for value in general_system_templates],
    "user_activity": [value[1] for value in user_activity_templates],
}

from template_log_parser import compile_templates, process_log
from template_workflows.functions.merge import merge_events

def synology_log(
    file: str | BytesIO | StringIO | TextIOBase,
) -> dict[str, pd.DataFrame]:
    """Workflow for Synology log files"""

    templates = compile_templates(base_synology_templates)

    base_output = process_log(
        file=file, templates=templates, dict_format=False, datetime_columns=["time"]
    )

    if "data_uploaded" in base_output.columns:
        base_output["data_uploaded_MB"] = base_output.apply(
            lambda row: (
                calc_data_usage(row["data_uploaded"], increment="MB")
                if isinstance(row["data_uploaded"], str)
                else pd.NA
            ),
            axis=1,
        )

    if "data_downloaded" in base_output.columns:
        base_output["data_download_MB"] = base_output.apply(
            lambda row: (
                calc_data_usage(row["data_downloaded"], increment="MB")
                if isinstance(row["data_downloaded"], str)
                else pd.NA
            ),
            axis=1,
        )

    if "client_ip" in base_output.columns:
        base_output["client_ip_address"] = base_output.apply(
            lambda row: (
                isolate_ip_from_parentheses(row["client_ip"])
                if isinstance(row["client_ip"], str)
                else pd.NA
            ),
            axis=1,
        )

    final_output = merge_events(base_output, synology_merge_events_dict)

    return final_output




