from io import BytesIO, StringIO, TextIOBase
import pandas as pd

from template_workflows.functions.column_functions import (
    calc_time,
    calc_data_usage,
    split_name_and_mac,
)

from template_workflows.functions.merge import merge_events

from template_workflows.templates.omada import (
    base_omada_templates,
    client_activity_templates,
    login_templates,
    network_devices_activity_templates,
    system_templates,
)

from template_log_parser import compile_templates, process_log

omada_merge_events_dict = {
    "client_activity": [value[1] for value in client_activity_templates],
    "logins": [value[1] for value in login_templates],
    "network_device_activity": [
        value[1] for value in network_devices_activity_templates
    ],
    "system": [value[1] for value in system_templates],
}


def omada_log(file: str | BytesIO | StringIO | TextIOBase) -> dict[str, pd.DataFrame]:
    """Workflow for Omada log files"""
    templates = compile_templates(base_omada_templates)

    base_output = process_log(
        file=file, templates=templates, dict_format=False, datetime_columns=["time"]
    )

    # Client connection time in minutes
    if "connected_time" in base_output.columns:
        base_output["conn_time_min"] = base_output.apply(
            lambda row: (
                calc_time(row["connected_time"], increment="minutes")
                if isinstance(row["connected_time"], str)
                else pd.NA
            ),
            axis=1,
        )

    # Client data usage in MegaBytes
    if "data" in base_output.columns:
        base_output["data_usage_MB"] = base_output.apply(
            lambda row: (
                calc_data_usage(row["data"], increment="MB")
                if isinstance(row["connected_time"], str)
                else pd.NA
            ),
            axis=1,
        )

    # Separate client name and mac for sorting
    if "client_name_and_mac" in base_output.columns:
        base_output[["client_name", "client_mac"]] = base_output.apply(
            lambda row: (
                split_name_and_mac(row["client_name_and_mac"])
                if isinstance(row["connected_time"], str)
                else (pd.NA, pd.NA)
            ),
            axis=1,
            result_type="expand",
        )

    final_output = merge_events(base_output, omada_merge_events_dict)

    return final_output
