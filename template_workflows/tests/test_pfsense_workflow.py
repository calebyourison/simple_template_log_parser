import unittest

from template_log_parser.definitions import event_type_column
from template_workflows.pfsense_workflow import pfsense_log, split_by_delimiter_column_pairs, pfsense_merge_events_dict
from test.resources import pfsense_sample_log

class TestPfsenseWorkflow(unittest.TestCase):
    """Defines a class to test the PfSense log workflow"""

    def test_pfsense_log(self):
        """Assert pfsense_log produces the expected events"""

        output = pfsense_log(pfsense_sample_log)

        df_lines = 0
        with open(pfsense_sample_log, "r") as f:
            total_lines = len(f.readlines())

        for df_name, event_types in pfsense_merge_events_dict.items():
            df = output[df_name]
            df_lines += df.shape[0]

            actual_event_types = sorted(df[event_type_column].unique().tolist())

            self.assertEqual(actual_event_types, sorted(set(event_types)))

            for old_column, new_columns in split_by_delimiter_column_pairs.items():
                # Old columns should be dropped
                self.assertTrue(old_column not in df.columns)
                # Verify the filter log df contains all the newly created columns
                if df_name == "filter_log":
                    for new_column in new_columns:
                        self.assertTrue(new_column in df.columns)

        self.assertEqual(total_lines, df_lines)