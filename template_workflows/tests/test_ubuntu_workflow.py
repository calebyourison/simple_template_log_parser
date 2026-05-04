import unittest

from template_workflows.ubuntu_workflow import ubuntu_log, ubuntu_merge_events_dict
from test.resources import ubuntu_debian_sample_log

from template_log_parser.definitions import event_type_column

class TestUbuntuWorkflow(unittest.TestCase):
    """Defines a class to test the Ubuntu log workflow"""

    def test_ubuntu_log(self):
        """Assert ubuntu_log correctly produces the expected events"""
        output = ubuntu_log(ubuntu_debian_sample_log)

        df_lines = 0
        with open(ubuntu_debian_sample_log, "r") as f:
            total_lines = len(f.readlines())

        for df_name, event_types in ubuntu_merge_events_dict.items():
            df = output[df_name]
            df_lines += df.shape[0]

            actual_event_types = sorted(df[event_type_column].unique().tolist())

            # Assert the expected event types are present
            self.assertEqual(actual_event_types, sorted(set(event_types)))

        self.assertEqual(total_lines, df_lines)
