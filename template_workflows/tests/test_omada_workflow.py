import unittest
import pandas as pd

from template_workflows.omada_workflow import omada_log, omada_merge_events_dict
from test.resources import omada_sample_log

from template_log_parser.definitions import event_type_column


class TestOmadaWorkflow(unittest.TestCase):
    """Defines a class to test the Omada log workflow"""

    def test_omada_log(self):
        """Assert omada_log correctly processes the expected columns"""
        column_types = {"conn_time_min": float, "data_usage_MB": float, "client_name": str, "client_mac":str}

        output = omada_log(omada_sample_log)

        df_lines = 0
        with open(omada_sample_log, "r") as f:
            total_lines = len(f.readlines())

        for df_name, event_types in omada_merge_events_dict.items():
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
                        if value is not pd.NA:
                            self.assertIsInstance(value, data_type)

        self.assertEqual(total_lines, df_lines)
