from template_workflows.templates.debian import base_debian_templates

openmediavault_id_process = "{time} {server_name} openmediavault-{process}[{id}]: {message}"
openmediavault_process = "{time} {server_name} openmediavault-{process} {message}"
omv_id_process = "{time} {server_name} omv-{process}[{id}]:{message}"
omv_process = "{time} {server_name} omv-{process}: {message}"
omv_id_process_2 = "{time} {server_name} omv-{process}[{id}]:"
conf = "{time} {server_name} conf_{version}: {message}"
php = "{time} {server_name} php{version}: {action}: {message}"
empty_samba_recycle = "{time} {server_name} samba-recycle-{id} Please wait, empty recyle bin of <{folder_path}> ..."


omv_process_templates = [
    [omv_id_process, "omv_id_process", " omv-"],
    [omv_process, "omv_process", "omv-"],
    [omv_id_process_2, "omv_id_process", "omv-"]
]

openmediavault_process_templates = [
    [openmediavault_id_process, "openmediavault_id_process", " openmediavault-"],
    [openmediavault_process, "openmediavault_process", "openmediavault-"],
]

omv_other_templates = [
    [conf, "conf", "conf_"],
    [php, 'php', "php"],
    [empty_samba_recycle, "empty_samba_recycle", "samba-recycle"]
]

base_omv_templates = omv_process_templates + openmediavault_process_templates + omv_other_templates + base_debian_templates
