# Base templates for PFSense Log Analysis
# Note: These templates adhere to syslog format

from template_log_parser.column_functions import split_by_delimiter

# Filter Log
filter_log_esp_ipv4 = '{time} {firewall} filterlog[{process_id}] {esp_ipv4_rule_info},4,{esp_ipv4_protocol_info},esp,{esp_ipv4_ip_info}'

filter_log_gre_ipv4 = '{time} {firewall} filterlog[{process_id}] {gre_ipv4_rule_info},4,{gre_ipv4_protocol_info},gre,{gre_ipv4_ip_info}'

filter_log_icmp_ip4_reply = '{time} {firewall} filterlog[{process_id}] {icmp_ipv4_rule_info},4,{icmp_ipv4_protocol_info},icmp,{icmp_ipv4_ip_info},reply,{icmp_ipv4_reply_info}'
filter_log_icmp_ipv4_request = '{time} {firewall} filterlog[{process_id}] {icmp_ipv4_rule_info},4,{icmp_ipv4_protocol_info},icmp,{icmp_ipv4_ip_info},request,{icmp_ipv4_request_info}'
filter_log_icmp_ipv4_type = '{time} {firewall} filterlog[{process_id}] {icmp_ipv4_rule_info},4,{icmp_ipv4_protocol_info},icmp,{icmp_ipv4_ip_info},type-{type}'
filter_log_icmp_ipv4_tstampreply = '{time} {firewall} filterlog[{process_id}] {icmp_ipv4_rule_info},4,{icmp_ipv4_protocol_info},icmp,{icmp_ipv4_ip_info},tstampreply,{icmp_ipv4_tstampreply_info}'
filter_log_icmp_ipv4_unreachport = '{time} {firewall} filterlog[{process_id}] {icmp_ipv4_rule_info},4,{icmp_ipv4_protocol_info},icmp,{icmp_ipv4_ip_info},unreachport,{icmp_ipv4_unreachport_info}'
filter_log_icmp_ipv4_unreachproto = '{time} {firewall} filterlog[{process_id}] {icmp_ipv4_rule_info},4,{icmp_ipv4_protocol_info},icmp,{icmp_ipv4_ip_info},unreachproto,{icmp_ipv4_unreachproto_info}'
filter_log_icmp_ipv4_unreach = '{time} {firewall} filterlog[{process_id}] {imcp_ipv4_rule_info},4,{icmp_ipv4_protocol_info},icmp,{icmp_ipv4_ip_info},unreach,{message}'
filter_log_icmp_ipv4_redirect = '{time} {firewall} filterlog[{process_id}] {icmp_ipv4_rule_info},4,{icmp_ipv4_protocol_info},icmp,{icmp_ipv4_ip_info},redirect,{message}'

filter_log_icmp_ipv6 = '{time} {firewall} filterlog[{process_id}] {icmp_ipv6_rule_info},6,{icmp_ipv6_protocol_info},ICMPv6,{icmp_ipv6_ip_info}'
filter_log_igmp_ipv4 = '{time} {firewall} filterlog[{process_id}] {igmp_ipv4_rule_info},4,{igmp_ipv4_protocol_info},igmp,{igmp_ipv4_ip_info}'

filter_log_tcp_ipv4_bad_options = '{time} {firewall} filterlog[{process_id}] {tcp_ipv4_rule_info},4,{tcp_ipv4_protocol_info},tcp,{tcp_ipv4_ip_info}[bad opt]{message}'
filter_log_tcp_ipv4_error = '{time} {firewall} filterlog[{process_id}] {tcp_ipv4_rule_info},4,{tcp_ipv4_protocol_info},tcp,{tcp_ipv4_error_ip_info},errormsg={message}'
filter_log_tcp_ipv4 = '{time} {firewall} filterlog[{process_id}] {tcp_ipv4_rule_info},4,{tcp_ipv4_protocol_info},tcp,{tcp_ipv4_ip_info}'
filter_log_udp_ipv4 = '{time} {firewall} filterlog[{process_id}] {udp_ipv4_rule_info},4,{udp_ipv4_protocol_info},udp,{udp_ipv4_ip_info}'

filter_log_ipv4_in_ipv4 = '{time} {firewall} filterlog[{process_id}] {ipv4_in_ipv4_rule_info},4,{ipv4_in_ipv4_protocol_info},ipencap,{ipv4_in_ipv4_ip_info},IPV4-IN-IPV4,'
filter_log_ipv6_in_ipv4 = '{time} {firewall} filterlog[{process_id}] {ipv6_in_ip4v_rule_info},4,{ipv6_in_ipv4_protocol_info},ipv6,{ipv4_in_ipv6_ip_info},IPV6-IN-IPV4,'

# General
cmd = '{time} {firewall} {source}[{process_id}] ({user}) CMD ({command})'
check_reload_status = '{time} {firewall} check_reload_status[{process_id}] {message}'
cron = '{time} {firewall} {path}cron[{process_id}] {message}'
dhclient = '{time} {firewall} dhclient[{process_id}] {message}'
dhcp_lfc = '{time} {firewall} DhcpLFC[{process_id}] {level}  {message}'
kea_dhcp4 = '{time} {firewall} kea-dhcp4[{process_id}] {levelt}  {message}'
kernel = "{time} {firewall} kernel {item}: {message}"
nginx = '{time} {firewall} nginx {dest_ip} - {user} [{timestamp}] "{type} {message}"'
nginx_error = '{time} {firewall} nginx {message_time} [error] {message}'
ntpd = '{time} {firewall} ntpd[{process_id}] {message}'
openvpn = '{time} {firewall} openvpn[{process_id}] {message}'
php = '{time} {firewall} php[{process_id}] {message}'
php_fpm = '{time} {firewall} php-fpm[{process_id}]{message}'
pkg_static = '{time} {firewall} pkg-static[{process_id}] {message}'
rc_gateway_alarm = '{time} {firewall} rc.gateway_alarm[{process_id}] {message}'
sudo = '{time} {firewall} sudo[{process_id}] {message}'
sshd = '{time} {firewall} sshd[{process_id}] {message}'
sasldblistusers2 = '{time} {firewall} sasldblistusers2[{process_id}] {message}'
saslpasswd2 = '{time} {firewall} saslpasswd2[{process_id}] {message}'
sshguard = '{time} {firewall} sshguard[{process_id}] {message}'
syslogd = '{time} {firewall} syslogd {message}'
unbound = '{time} {firewall} unbound[{process_id}] {message}'

filter_log_dict = {
    'esp': [filter_log_esp_ipv4, 6, 'filter_esp_ipv4'],

    'gre': [filter_log_gre_ipv4, 6, 'filter_gre_ipv4'],

    'type': [filter_log_icmp_ipv4_type, 7, 'filter_icmp_ipv4_type'],
    'reply': [filter_log_icmp_ip4_reply, 7, 'filter_icmp_ipv4_reply'],
    'request': [filter_log_icmp_ipv4_request, 7, 'filter_icmp_ipv4_request'],
    'tstampreply': [filter_log_icmp_ipv4_tstampreply, 7, 'filter_icmp_ipv4_tstampreply'],
    'unreachport': [filter_log_icmp_ipv4_unreachport, 7, 'filter_icmp_ipv4_unreachport'],
    'unreachproto': [filter_log_icmp_ipv4_unreachproto, 7, 'filter_icmp_ipv4_unreachproto'],
    'unreach,': [filter_log_icmp_ipv4_unreach, 7, 'filter_icmp_ipv4_unreach'],
    'redirect': [filter_log_icmp_ipv4_redirect, 7, 'filter_icmp_ipv4_redirect'],
    'ICMPv6': [filter_log_icmp_ipv6, 6, 'filter_icmp_ipv6'],
    'igmp': [filter_log_igmp_ipv4, 6, 'filter_igmp_ipv4'],

    'tcp,': [filter_log_tcp_ipv4_error, 7, 'filter_tcp_ipv4_error'], # Search these templates before the standard tcp ipv4 template
    ',tcp': [filter_log_tcp_ipv4_bad_options, 7, 'filter_tcp_ipv4_bad_options'],
    'tcp': [filter_log_tcp_ipv4, 6, 'filter_tcp_ipv4'], # Standard tcp ipv4 template

    'udp': [filter_log_udp_ipv4, 6, 'filter_udp_ipv4'],
    'IPV6-IN-IPV4': [filter_log_ipv6_in_ipv4, 6, 'filter_ipv6_in_ip4v'],
    'IPV4-IN-IPV4': [filter_log_ipv4_in_ipv4, 6, 'filter_ipv4_in_ipv4'],
}

general_dict = {
    'CMD': [cmd, 6, 'cmd'],
    'check_reload_status': [check_reload_status, 4, 'check_reload_status'],
    'cron': [cron, 5, 'cron'],
    'dhclient': [dhclient, 4, 'dhclient'],
    'kea-dhcp4': [kea_dhcp4, 5, 'kea_dhcp4'],
    'kernel': [kernel, 4, 'kernel'],
    'DhcpLFC': [dhcp_lfc, 5, 'dhcp_lfc'],
    'nginx': [nginx, 7, 'nginx'],
    'error': [nginx_error, 4, 'nginx_error'],
    'ntpd': [ntpd, 4, 'ntpd'],
    'openvpn[': [openvpn, 4, 'openvpn'],
    'pkg-static': [pkg_static, 4, 'pkg_static'],
    'php[': [php, 4, 'php'],
    'php-fpm': [php_fpm, 4, 'php_fpm'],
    'rc.gateway_alarm': [rc_gateway_alarm, 4, 'rc_gateway_alarm'],
    'sasldblistusers2': [sasldblistusers2, 4, 'sasldblistusers2'],
    'saslpasswd2': [saslpasswd2, 4, 'saslpasswd2'],
    'sudo': [sudo, 4, 'sudo'],
    'sshd': [sshd, 4, 'sshd'],
    'sshguard': [sshguard, 4, 'ssh_guard'],
    'syslogd': [syslogd, 3, 'syslogd'],
    'unbound': [unbound, 4, 'unbound'],


}

pfsense_template_dict = {**filter_log_dict, **general_dict}

# Rule Columns
generic_rule_info_columns = ['rule_number', 'sub_rule', 'anchor', 'tracker', 'real_interface', 'reason', 'action', 'direction']

# Protocol Columns
generic_ipv4_protocol_info_columns = ['tos', 'ecn', 'ttl', 'id', 'offset', 'flags', 'protocol_id']
icmp_ipv6_protocol_info_columns = ['class', 'flow_label', 'hop_limit']

# IP Info Columns
generic_ipv4_ip_info_columns = ['length', 'src_ip', 'dest_ip', 'data_length']
icmp_ipv4_ip_info_columns = ['length', 'src_ip', 'dest_ip']
icmp_ipv6_ip_info_columns = ['protocol_id', 'length', 'src_ip', 'dest_ip', 'icmp_data']
tcp_ipv4_ip_info_error_columns = ['length', 'src_ip', 'dest_ip', 'src_port', 'dest_port', 'data_length', 'tcp_flags']
tcp_ipv4_ip_info_columns = ['length', 'src_ip', 'dest_ip', 'src_port', 'dest_port', 'data_length', 'tcp_flags', 'seq_number', 'ack_number', 'tcp_window', 'urg', 'tcp_options']
udp_ipv4_ip_info_columns = ['length', 'src_ip', 'dest_ip', 'src_port', 'dest_port', 'data_length']

# Instance specific Columns
icmp_ipv4_generic_info_columns = ['icmp_id', 'icmp_sequence']
icmp_ipv4_unreachport_info_columns = ['icmp_dest_ip', 'unreach_protocol', 'unreach_port']
icmp_ipv4_unreachproto_info_columns = ['icmp_dest_ip', 'unreach_protocol']
icmp_ipv4_tstampreply_info_columns = ['icmp_id', 'icmp_sequence', 'icmp_otime', 'icmp_rtime', 'icmp_ttime']

pfsense_column_process_dict = {
    'esp_ipv4_rule_info': [split_by_delimiter, generic_rule_info_columns],
    'esp_ipv4_protocol_info': [split_by_delimiter, generic_ipv4_protocol_info_columns],
    'esp_ipv4_ip_info': [split_by_delimiter, generic_ipv4_ip_info_columns],


    'gre_ipv4_rule_info': [split_by_delimiter, generic_rule_info_columns],
    'gre_ipv4_protocol_info': [split_by_delimiter, generic_ipv4_protocol_info_columns],
    'gre_ipv4_ip_info': [split_by_delimiter, generic_ipv4_ip_info_columns],

    'icmp_ipv4_rule_info': [split_by_delimiter, generic_rule_info_columns],
    'icmp_ipv4_protocol_info': [split_by_delimiter, generic_ipv4_protocol_info_columns],
    'icmp_ipv4_ip_info' : [split_by_delimiter, icmp_ipv4_ip_info_columns],

    'icmp_ipv4_reply_info': [split_by_delimiter, icmp_ipv4_generic_info_columns],
    'icmp_ipv4_request_info': [split_by_delimiter, icmp_ipv4_generic_info_columns],
    'icmp_ipv4_tstampreply_info': [split_by_delimiter, icmp_ipv4_tstampreply_info_columns],
    'icmp_ipv4_unreachport_info': [split_by_delimiter, icmp_ipv4_unreachport_info_columns],
    'icmp_ipv4_unreachproto_info' : [split_by_delimiter, icmp_ipv4_unreachproto_info_columns],

    'icmp_ipv6_rule_info': [split_by_delimiter, generic_rule_info_columns],
    'icmp_ipv6_protocol_info': [split_by_delimiter, icmp_ipv6_protocol_info_columns],
    'icmp_ipv6_ip_info': [split_by_delimiter, icmp_ipv6_ip_info_columns],

    'igmp_ipv4_rule_info': [split_by_delimiter, generic_rule_info_columns],
    'igmp_ipv4_protocol_info': [split_by_delimiter, generic_ipv4_protocol_info_columns],
    'igmp_ipv4_ip_info': [split_by_delimiter, generic_ipv4_ip_info_columns],

    "tcp_ipv4_rule_info": [split_by_delimiter, generic_rule_info_columns],
    'tcp_ipv4_protocol_info': [split_by_delimiter, generic_ipv4_protocol_info_columns],
    'tcp_ipv4_ip_info': [split_by_delimiter, tcp_ipv4_ip_info_columns],
    'tcp_ipv4_error_ip_info': [split_by_delimiter, tcp_ipv4_ip_info_error_columns],

    'udp_ipv4_rule_info': [split_by_delimiter, generic_rule_info_columns],
    'udp_ipv4_protocol_info': [split_by_delimiter, generic_ipv4_protocol_info_columns],
    'udp_ipv4_ip_info': [split_by_delimiter, udp_ipv4_ip_info_columns],

    'ipv6_in_ip4v_rule_info': [split_by_delimiter, generic_rule_info_columns],
    'ipv6_in_ipv4_protocol_info': [split_by_delimiter, generic_ipv4_protocol_info_columns],
    'ipv4_in_ipv6_ip_info': [split_by_delimiter, icmp_ipv4_ip_info_columns],

    'ipv4_in_ipv4_rule_info': [split_by_delimiter, generic_rule_info_columns],
    'ipv4_in_ipv4_protocol_info': [split_by_delimiter, generic_ipv4_protocol_info_columns],
    'ipv4_in_ipv4_ip_info': [split_by_delimiter, icmp_ipv4_ip_info_columns],

    }

pfsense_merge_events_dict = {
    "filter_log": [value[2] for value in filter_log_dict.values()],
    'general': [value[2] for value in general_dict.values()],
}
