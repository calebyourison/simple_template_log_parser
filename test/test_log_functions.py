import unittest
import pandas as pd
from pandas.api.types import is_datetime64_any_dtype
from io import StringIO, BytesIO
from contextlib import redirect_stdout, redirect_stderr

from parse import compile as parse_compile

from template_log_parser.definitions import SimpleTemplate

from template_log_parser.template_functions import compile_templates

from template_log_parser.log_functions import parse_function, filter_line, log_pre_process, process_log

from template_log_parser.definitions import (
    event_type_column,
    event_data_column,
    other_type_column,
    unparsed_text_column,
)

from test.resources import logger

from test.resources import (
    debian_sample_log,
    kodi_sample_log,
    omada_sample_log,
    omv_debian_sample_log,
    pfsense_sample_log,
    pihole_sample_log,
    synology_sample_log,
    ubuntu_debian_sample_log
)

from template_workflows.templates.debian import base_debian_templates
from template_workflows.templates.kodi import base_kodi_templates
from template_workflows.templates.omada import base_omada_templates
from template_workflows.templates.omv import base_omv_templates
from template_workflows.templates.pfsense import base_pfsense_templates
from template_workflows.templates.pihole import base_pihole_templates
from template_workflows.templates.synology import base_synology_templates
from template_workflows.templates.ubuntu import base_ubuntu_templates

template_pairs = {
    "debian": {"templates": base_debian_templates, "file": debian_sample_log},
    "kodi": {"templates": base_kodi_templates, "file": kodi_sample_log},
    "omada": {"templates": base_omada_templates, "file": omada_sample_log},
    "omv": {"templates": base_omv_templates, "file": omv_debian_sample_log},
    "pfsense": {"templates": base_pfsense_templates, "file": pfsense_sample_log},
    "pihole": {"templates": base_pihole_templates, "file": pihole_sample_log},
    "synology": {"templates": base_synology_templates, "file": synology_sample_log},
    "ubuntu": {"templates": base_ubuntu_templates, "file": ubuntu_debian_sample_log}
}

class TestPreProcessFunctions(unittest.TestCase):
    """Defines a class to test log functions"""

    def test_parse_function(self):
        """Test function to assert that parse function is returning a string event type and a dictionary of results"""
        # Known event type with a verified template
        simple_event = (
            "2024-09-12T00:28:49.037352+01:00 gen_controller  2024-09-11 16:28:44 Controller - - - "
            "user logged in to the controller from 172.0.0.1."
        )

        temp = (
            "{timestamp} {controller_name}  {local_time} Controller - - - "
            "{username} logged in to the controller from {ip}."
        )

        simple_template_list = [SimpleTemplate(template=parse_compile(temp), event_type="login", search_string="logged in")]

        results = parse_function(simple_event, simple_template_list)
        self.assertIsInstance(results, dict)
        self.assertEqual(results[event_type_column], "login")

        # Should return tuple, then string and dict respectively
        anomalous_event = "This event does not match any template."
        # Unknown event type should also pass without error, return dict
        results_2 = parse_function(anomalous_event, simple_template_list)
        self.assertIsInstance(results_2, dict)
        # Should return other event type
        self.assertEqual(results_2[event_type_column], other_type_column)
        # The key to its dict should be unparsed_text_column, event_type_column
        self.assertEqual(list(results_2.keys()), [unparsed_text_column, event_type_column])

    def test_filter_line(self):
        """Test function to assert that filter_line returns the correct boolean"""
        sample_line = "It was the best of times. It was the worst of times."

        # No input should be True
        self.assertTrue(filter_line(sample_line))

        combinations = [
            {"match_type": "any", "match": ["times", "spaceship", "earth"], "result": True},
            {"match_type": "all", "match": ["times", "best", "worst", "It"], "result": True},
            {"match_type": "any", "match": "earth", "result": False},
            {"match_type": "all", "match": ["times", "earth"], "result": False},
            {"eliminate_type": "any", "eliminate": ["earth", "mars", "saturn"], "result": True},
            {"eliminate_type": "all", "eliminate":["best", "times", "earth"], "result": True},
            {"eliminate_type": "any", "eliminate": ["best", "times", "earth"], "result": False},
            {"eliminate_type": "all", "eliminate": ["best", "times", "worst"], "result": False},
            {"eliminate_type": "any", "eliminate": ["best"], "match_type": "any", "match": ["best"], "result": False}
        ]

        for combination in combinations:
            match_type = combination.get("match_type", "any")
            eliminate_type = combination.get("eliminate_type", "any")
            match = combination.get("match", None)
            eliminate = combination.get("eliminate", None)
            expected_result = combination.get("result")

            result = filter_line(line=sample_line, match_type=match_type, eliminate_type=eliminate_type, match=match, eliminate=eliminate)

            if expected_result:
                self.assertTrue(result, combination)

            else:
                self.assertFalse(result, combination)


    def test_log_pre_process(self):
        """Test function to assert that log_pre_process returns a Pandas DataFrame with expected columns"""
        for name, attributes in template_pairs.items():
            logger.info(f"Checking {name} templates: log_pre_process")
            templates = attributes.get("templates", [])

            file_types = list()
            file = attributes.get("file", "")

            # String
            file_types.append(file)

            # BytesIO
            with open(file, "rb") as f:
                bytes_io_file = BytesIO(f.read())
                file_types.append(bytes_io_file)

            # StringIO
            with open(file, "r") as f:
                lines = f.read()
                string_io_file = StringIO(lines)
                file_types.append(string_io_file)

            # Number of lines to account for
            with open(file, "r") as f:
                number_of_lines = len(f.readlines())

            self.assertEqual(len(templates), number_of_lines)
            logger.info("Length of template dictionary matches the length of logfile")

            compiled_templates = compile_templates(templates)

            expected_events = []
            expected_columns = []
            for template in compiled_templates:
                columns = template.template.named_fields
                for column in columns:
                    expected_columns.append(column)

                expected_events.append(template.event_type)

            expected_columns.extend([event_data_column, event_type_column])

            # Eliminate duplicate columns
            expected_columns = sorted(set(expected_columns))

            # Do no eliminate duplicates, more than one template can share an event type
            expected_events = sorted(expected_events)

            for f in file_types:
                output = log_pre_process(file=f, templates=compiled_templates)

                actual_columns = sorted(output.columns)

                self.assertIsInstance(output, pd.DataFrame)

                self.assertEqual(expected_columns, actual_columns)
                logger.info(f"Expected {expected_columns} columns, found {actual_columns}")

                actual_events = sorted(output[event_type_column])
                self.assertEqual(expected_events, actual_events)

                self.assertEqual(output.shape[0], number_of_lines)
                logger.info(f"Expected {number_of_lines} rows in dataframe, found {output.shape[0]}")

                # Print all lines that are not accounted for by templates
                other = output[output[event_type_column] == other_type_column]
                logger.debug(f"Unparsed Lines: {other}")

                # Assert no "Other" event types
                self.assertTrue(other_type_column not in output[event_type_column].tolist())

                criteria = "open"

                matched_output = log_pre_process(file=f, templates=compiled_templates, match=criteria)
                for index, row in matched_output.iterrows():
                    message = row[event_data_column]
                    self.assertTrue(criteria in message)

                eliminated_output = log_pre_process(file=f, templates=compiled_templates, eliminate=criteria)
                for index, row in eliminated_output.iterrows():
                    message = row[event_data_column]
                    self.assertTrue(criteria not in message)

            improper_file_type = {}
            self.assertRaises(
                ValueError,
                log_pre_process,
                improper_file_type,
                compiled_templates
            )

    def test_process_log(self):
        """Test function to assert that process_log returns the expected output"""
        no_datetime_columns = ["pihole"]

        for name, attributes in template_pairs.items():
            logger.info(f"Checking {name} templates: process_log")
            templates = attributes.get("templates", [])

            if name not in no_datetime_columns:
                date_time_column = ["time"]
            else:
                date_time_column = None

            file_types = list()
            file = attributes.get("file", "")

            # String
            file_types.append(file)

            # BytesIO
            with open(file, "rb") as f:
                bytes_io_file = BytesIO(f.read())
                file_types.append(bytes_io_file)

            # StringIO
            with open(file, "r") as f:
                lines = f.read()
                string_io_file = StringIO(lines)
                file_types.append(string_io_file)

            # Number of lines to account for
            with open(file, "r") as f:
                number_of_lines = len(f.readlines())

            self.assertEqual(len(templates), number_of_lines)
            logger.info("Length of template dictionary matches the length of logfile")

            compiled_templates = compile_templates(templates)

            # Dictionary format
            for f in file_types:
                dict_output = process_log(f, compiled_templates, dict_format=True, datetime_columns=date_time_column)

                expected_columns_per_key = {}
                expected_keys = []
                for template in compiled_templates:
                    key = template.event_type
                    expected_keys.append(key)
                    # Same event type might have multiple templates with different columns
                    if key in expected_columns_per_key.keys():
                        expected_columns_per_key[key].extend(template.template.named_fields)
                    else:
                        expected_columns_per_key[key] = template.template.named_fields
                        expected_columns_per_key[key] += [event_type_column, event_data_column]

                # Remove duplicates
                expected_keys = sorted(set(expected_keys))
                logger.debug(f"Expected keys {len(expected_keys)}: {expected_keys}")
                actual_keys = sorted(dict_output.keys())
                logger.debug(f"Actual keys {len(actual_keys)}: {actual_keys}")

                self.assertEqual(expected_keys, actual_keys)

                for key in expected_columns_per_key:
                    logger.debug(f"Checking key {key}")

                    # Remove duplicates
                    expected_columns = sorted(list(set(expected_columns_per_key[key])))
                    logger.debug(f"Expected columns: {len(expected_columns)}: {expected_columns}")

                    mini_df = dict_output[key]
                    actual_columns = sorted(mini_df.columns)
                    logger.debug(f"Actual columns: {len(actual_columns)}: {actual_columns}")

                    self.assertEqual(expected_columns, actual_columns)

                    if date_time_column:
                        self.assertTrue(is_datetime64_any_dtype(mini_df["time"]))

            # DF version
            # dt conversion error, dt localization error, nothing raised, just print statements
            f = StringIO()
            f_err = StringIO()

            with redirect_stdout(f), redirect_stderr(f_err):
                output = process_log(file, compiled_templates, dict_format=False, datetime_columns=[event_type_column])
                self.assertIsInstance(output, pd.DataFrame)

            print_statement = f.getvalue()

            self.assertTrue("Error converting column" in print_statement)
            self.assertTrue("to datetime:" in print_statement)

            # Ensure no matches pass without error when dict=True
            no_matches = process_log(f, compiled_templates, dict_format=True, match=["unlikely", "to", "match", "dfds"], match_type="all")
            self.assertEqual(no_matches, {})
