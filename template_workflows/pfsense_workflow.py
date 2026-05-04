from io import BytesIO, StringIO, TextIOBase
import pandas as pd

from template_workflows.functions.column_functions import split_by_delimiter
from template_workflows.functions.merge import merge_events
from template_workflows.templates.pfsense import base_pfsense_templates, filter_log_templates, general_templates
from template_log_parser import compile_templates, process_log

# Rule Columns
generic_rule_info_columns = [
    "rule_number",
    "sub_rule",
    "anchor",
    "tracker",
    "real_interface",
    "reason",
    "action",
    "direction",
]

# Protocol Columns
generic_ipv4_protocol_info_columns = [
    "tos",
    "ecn",
    "ttl",
    "id",
    "offset",
    "flags",
    "protocol_id",
]

icmp_ipv6_protocol_info_columns = ["class", "flow_label", "hop_limit"]

# IP Info Columns
base_ipv4_ip_info_columns = ["length", "src_ip", "dest_ip"]

generic_ipv4_ip_info_columns = base_ipv4_ip_info_columns + ["data_length"]

base_ipv4_tcp_udp_ip_info_columns = base_ipv4_ip_info_columns + [
    "src_port",
    "dest_port",
    "data_length",
]

tcp_ipv4_ip_info_error_columns = base_ipv4_tcp_udp_ip_info_columns + ["tcp_flags"]

tcp_ipv4_ip_info_columns = base_ipv4_tcp_udp_ip_info_columns + [
    "tcp_flags",
    "seq_number",
    "ack_number",
    "tcp_window",
    "urg",
    "tcp_options",
]

icmp_ipv6_ip_info_columns = ["protocol_id", "length", "src_ip", "dest_ip", "icmp_data"]

# Instance specific Columns
icmp_ipv4_generic_info_columns = ["icmp_id", "icmp_sequence"]

icmp_ipv4_unreachport_info_columns = [
    "icmp_dest_ip",
    "unreach_protocol",
    "unreach_port",
]
icmp_ipv4_unreachproto_info_columns = ["icmp_dest_ip", "unreach_protocol"]

icmp_ipv4_tstampreply_info_columns = [
    "icmp_id",
    "icmp_sequence",
    "icmp_otime",
    "icmp_rtime",
    "icmp_ttime",
]

split_by_delimiter_column_pairs = {
    # Generic
    "rule_info": generic_rule_info_columns,
    "ipv4_protocol_info": generic_ipv4_protocol_info_columns,
    "ipv4_ip_info": generic_ipv4_ip_info_columns,
    # ICMP
    "icmp_ipv4_ip_info": base_ipv4_ip_info_columns,
    "icmp_ipv4_reply_info": icmp_ipv4_generic_info_columns,
    "icmp_ipv4_request_info": icmp_ipv4_generic_info_columns,
    "icmp_ipv4_tstamp_info": icmp_ipv4_generic_info_columns,
    "icmp_ipv4_tstampreply_info": icmp_ipv4_tstampreply_info_columns,
    "icmp_ipv4_unreachport_info": icmp_ipv4_unreachport_info_columns,
    "icmp_ipv4_unreachproto_info": icmp_ipv4_unreachproto_info_columns,
    "icmp_ipv6_protocol_info": icmp_ipv6_protocol_info_columns,
    "icmp_ipv6_ip_info": icmp_ipv6_ip_info_columns,
    # SCTP
    "sctp_ipv4_ip_info": base_ipv4_tcp_udp_ip_info_columns,
    # TCP
    "tcp_ipv4_ip_info": tcp_ipv4_ip_info_columns,
    "tcp_ipv4_error_ip_info": tcp_ipv4_ip_info_error_columns,
    # UDP
    "udp_ipv4_ip_info": base_ipv4_tcp_udp_ip_info_columns,
    # IPv4 in IPv6, IPv4 in IPv4, etc
    "ipv4_in_ipv6_ip_info": base_ipv4_ip_info_columns,
    "ipv4_in_ipv4_ip_info": base_ipv4_ip_info_columns,
}

pfsense_merge_events_dict = {
    "filter_log": [value[1] for value in filter_log_templates],
    "general": [value[1] for value in general_templates]
}

def pfsense_log(file: str | BytesIO | StringIO | TextIOBase) -> dict[str, pd.DataFrame]:
    """Workflow for PfSense log files"""
    templates = compile_templates(base_pfsense_templates)

    base_output = process_log(
        file=file, templates=templates, dict_format=False, datetime_columns=["time"]
    )

    # Split at commas and create new columns, pd.NA where needed
    for column, new_columns in split_by_delimiter_column_pairs.items():
        if column in base_output.columns:
            base_output[new_columns] = base_output.apply(
                lambda row: (
                    split_by_delimiter(row[column])
                    if isinstance(row[column], str)
                    else tuple([pd.NA for col in new_columns])
                ),
                axis=1,
                result_type="expand",
            )

            base_output = base_output.drop(columns=[column])


    final_output = merge_events(base_output, pfsense_merge_events_dict)

    return final_output
