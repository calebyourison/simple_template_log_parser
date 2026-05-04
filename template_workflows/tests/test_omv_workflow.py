import unittest

from template_workflows.omv_workflow import omv_log, omv_merge_events_dict
from test.resources import omv_debian_sample_log

from template_log_parser.definitions import event_type_column

class TestOMVWorkflow(unittest.TestCase):
    """Defines a class to test the OMV log workflow"""

    def test_omv_log(self):
        """Assert omv_log correctly produces the expected events"""
        output = omv_log(omv_debian_sample_log)

        df_lines = 0
        with open(omv_debian_sample_log, "r") as f:
            total_lines = len(f.readlines())

        for df_name, event_types in omv_merge_events_dict.items():
            df = output[df_name]
            df_lines += df.shape[0]

            actual_event_types = sorted(df[event_type_column].unique().tolist())

            # Assert the expected event types are present
            self.assertEqual(actual_event_types, sorted(set(event_types)))

        self.assertEqual(total_lines, df_lines)
