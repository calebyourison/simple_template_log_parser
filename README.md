# template-log-parser : Log Files into Tabular Data
---
`template-log-parser` is designed to pull relevant information into DataFrame columns by way of user designed templates.  [parse](https://pypi.org/project/parse/) and [pandas](https://pypi.org/project/pandas/) perform the heavy lifting.

You can utilize the included [workflows](https://github.com/calebyourison/simple_template_log_parser/tree/master/template_workflows) (Kodi, Omada Controller, Open Media Vault, PFSense, PiHole, Synology DSM, and Ubuntu) or build your own. 

## Getting Started
---

```
pip install template-log-parser
```

---

The foundational principle in this project is designing templates that fit repetitive log file formats.


```
my_log_line = "2024-06-13T15:09:35 server_15 login_authentication[12345] rejected login from user[user_1]."

my_template = "{time} {server_name} {service_process}[{service_id}] {result} login from user[{username}]."
```

The words within the braces will eventually become column names in a DataFrame.  
Note that templates will be looking for an exact match.

---
After creating a list of templates, they should be compiled:

- 'search_string' is text expected to be found in the log file line.  The parsing function will only check the template against the line if the text is present.
- 'template' is the user defined template.
- 'event_type' is an arbitrary string name assigned to this type of occurrence.

```
from template_log_parser import compile_templates

uncompiled_templates = [
# [template, event_type, search_string ]
  [my_template, "login_attempt", "login from"],
  [my_template2, "reboot", "Host Restarting"],
  ...
]

my_templates = compile_templates(uncompiled_templates)

```
---

Parse an entire log file and return a Pandas DataFrame:
```
from template_log_parser import process_log

df = process_log('log_file.log', my_templates)

print(df.columns)
Index(['time', 'server_name', 'service_process', 'service_id', 'result', 'username', 'event_type', 'event_data'])
```
This is just a tabular data form of many single parsed events.
 - event_type column value is determined based on the matching template
 - event_data column holds the raw string data for each log line
 
Note: 
Events that do not match a template will be evaluated as event_type ('Other') with column: ('Unparsed_text').

---
## DISCLAIMER

**This project is in no way affiliated with the products mentioned (Debian, Kodi, Omada, Open Media Vault, PFSense, PiHole, Synology, or Ubuntu).
Any usage of their services is subject to their respective terms of use.**
