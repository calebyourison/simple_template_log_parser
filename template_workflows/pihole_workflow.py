from io import BytesIO, StringIO, TextIOBase
import pandas as pd

from template_workflows.templates.pihole import (
    base_pihole_templates,
    dnsmasq_templates,
    ftl_templates,
    webserver_templates,
    gravity_templates
)
from template_workflows.functions.merge import merge_events
from template_log_parser import compile_templates, process_log

pihole_merge_events_dict = {
    "dnsmasq": [value[1] for value in dnsmasq_templates],
    "ftl": [value[1] for value in ftl_templates],
    "webserver": [value[1] for value in webserver_templates],
    "gravity": [value[1] for value in gravity_templates]
}


def pihole_log(file: str | BytesIO | StringIO | TextIOBase, template_prefix:str="") -> dict[str,pd.DataFrame]:
    """Workflow for PiHole log files"""
    modified_templates = [[template_prefix + item[0]] + item[1:] for item in base_pihole_templates]

    templates = compile_templates(modified_templates)

    output = process_log(file=file, templates=templates, dict_format=False)

    final_output = merge_events(output, pihole_merge_events_dict)

    return final_output
