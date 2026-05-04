import unittest

from template_workflows.pihole_workflow import pihole_log, pihole_merge_events_dict
from test.resources import pihole_sample_log

from template_log_parser.definitions import event_type_column

class TestPiholeWorkflow(unittest.TestCase):
    """Defines a class to test the PiHole log workflow"""

    def test_pihole_log(self):
        """Assert pihole_log produces the expected events"""

        output = pihole_log(pihole_sample_log)
        df_lines = 0
        with open(pihole_sample_log, "r") as f:
            total_lines = len(f.readlines())

        for df_name, event_types in pihole_merge_events_dict.items():
            df = output[df_name]
            df_lines += df.shape[0]

            actual_event_types = sorted(df[event_type_column].unique().tolist())

            # Assert the expected event types are present
            self.assertEqual(actual_event_types, sorted(set(event_types)))

        self.assertEqual(total_lines, df_lines)