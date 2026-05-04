import unittest
import pandas as pd

from template_workflows.synology_workflow import synology_log, synology_merge_events_dict
from test.resources import synology_sample_log

from template_log_parser.definitions import event_type_column

class TestSynologyWorkflow(unittest.TestCase):
    """Defines a class to test the Synology log workflow"""

    def test_synology_log(self):
        """Assert synology_log correctly processes the expected columns"""
        column_types = {"data_uploaded_MB": float, "data_download_MB": float, "client_ip_address": str}

        output = synology_log(synology_sample_log)

        df_lines = 0
        with open(synology_sample_log, "r") as f:
            total_lines = len(f.readlines())

        for df_name, event_types in synology_merge_events_dict.items():
            df = output[df_name]
            df_lines += df.shape[0]

            actual_event_types = sorted(df[event_type_column].unique().tolist())

            # Assert the expected event types are present
            self.assertEqual(actual_event_types, sorted(set(event_types)))

            # Verify correct data types for processed columns
            for column, data_type in column_types.items():
                if column in df.columns:
                    series = df[column]
                    for value in series:
                        if pd.notna(value):
                            self.assertIsInstance(value, data_type)

        self.assertEqual(total_lines, df_lines)