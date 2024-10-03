# simple_template_log_parser : Log Files into Tabular Data
---
`simple_template_log_parser` is designed to streamline the log analysis process by pulling relevant information into DataFrame columns by way of user designed templates.  `parse` and `pandas` are the only dependencies. Full credit to those well-designed projects.

This project offers some flexibility in how you can process your log files.  You can utilize built-in template functions (Omada Controller, Synology DSM) or build your own method. 


#### Getting Started
---
The foundational principle in this project is designing templates that fit repetitive log file formats.

Example log line:
```bash
my_line = '2024-06-13T15:09:35 server_15 login_authentication[12345] rejected login from user[user_1].'
```
    
Example template:
```bash
template = '{time} {server_name} {service_process}[{service_id}] {result} login from user[{username}].'
```

The words within the braces will eventually become column names in a DataFrame.  You can capture as much or as little data from the line as you see fit.  For instance, you could opt to omit {result} from the template and thus look to match only rejected logins for this example.

Note that templates will be looking for an exact match.  Items like timestamps, time elapsed, and data used should be captured as they are unique to that log line instance.

#### Template Dictionaries
---
After creating templates, they should be added to a dictionary with the following format:
```bash
ex_dict = {'search_string': [template_name, expected_values, 'event_name'], ...}
```

Using the example template:
```bash
my_template_dict = {'login from': [template, 6, 'login_attempt'], ...}
```
- 'search_string' will be text that was NOT enclosed in braces {}. The parsing function will first check if this text is present within the log line before attempting to check the template against it.
- template_name is the user defined template
- expected_values is the integer number of items enclosed with braces {}.
- 'event_name' is the arbitrary name assigned to this type of occurrence

#### Basic Usage Examples
---
Parse a single event:
```bash
from simple_template_log_parser import parse_function
event_name, parsed_info = parse_function(my_line, my_template_dict)

print(event_name)
'login_attempt' 

print(parsed_info)
    {
    'time': '2024-06-13T15:09:35',
    'server_name': 'server_15',
    'service_process': 'login_authentication', 
    'service_id': '12345',
    'result': 'rejected',
    'username': 'user_1'
    }
```
Parse an entire log file and return a Pandas DataFrame:
```bash
from simple_template_log_parse import log_pre_process
df = log_pre_process('log_file.log', my_template_dict)

print(df.columns)
Index(['event_data', 'event_type', 'parsed_info'])
```
This just a tabular data form of many single parsed events.
 - event_data column holds the raw string data for each log line
 - event_type column value is determined based on the matching template
 - parsed_info column holds a dictionary of the parsed details
 
Note: 
Events that do not match a template will be returned as event_type ('Other') with a parsed_info dictionary:
{'unparsed_text': (original log file line)}

#### Granular Log Processing
---
Essentially, each key from the parsed_info dictionary will become its own column populated with the associated value.

By default, this procedure returns a dictionary of Pandas DataFrames, formatted as {'event_type': df}.

```bash
from simple_template_log_parser import process_log
my_df_dict = process_log('log_file.log', my_template_dict)

print(my_df_dict.keys())
dict_keys(['login_attempt', 'event_type_2', 'event_type_3'...])
```

Alternatively as one large DataFrame:
```bash
from simple_template_log_parser import process_log
my_df = process_log('log_file.log', my_template_dict, dict_format=False)

print(my_df.columns
Index(['event_type', 'time', 'server_name', 'service_process', 'service_id', 'result', 'username'])
```

###### Some Notes
---
- By default `drop_columns=True` which instructs `process_log()` to discard 'event_data' and 'parsed_info' along with any other columns modified by column functions (SEE NEXT).
- (OPTIONAL ARGUMENT) `additional_column_functions` allows user to apply functions to specific columns.  The original column will be deleted if `drop_columns=True`.  This argument takes a dictionary formatted as:
```bash
add_col_func = {column_to_run_function_on: [function, new_column_name_OR_list_of_new_colum_names]}
 ```
- (OPTIONAL ARGUMENT) `merge_dictionary` allows user to concatenate DataFrames that are deemed to be related.  Original DataFrames will be discarded, and the newly merged DF will be available within the dictionary by its new key.  This argument takes a dictionary formatted as:
```bash
my_merge_dict = {'new_df_key': [df_1_key, df_2_key, ...], ...}
```
- (OPTIONAL ARGUMENT) `datetime_columns` takes a list of columns that should be converted using `pd.to_datetime()`
- (OPTIONAL ARGUMENT) `localize_time_columns` takes a list of columns whose timezone should be eliminated (column must also be included in the `datetime_columns` argument).
---
#### Built-Ins
This project includes log process functions for Omada Controller, and Synology DSM, though these are still being actively developed as not all event types have been accounted for.
```bash
from simple_template_log_parser.omada import omada_process_log

my_omada_log_dict = omada_process_log('omada.log')

```

```bash
from simple_template_log_parse.synology import synology_process_log

my_synology_log_dict = synology_process_log('synology.log')