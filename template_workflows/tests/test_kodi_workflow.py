import unittest

from template_workflows.kodi_workflow import kodi_log, kodi_merge_events_dict
from test.resources import kodi_sample_log

from template_log_parser.definitions import event_type_column

class TestKodiWorkflow(unittest.TestCase):
    """Defines a class to test the Kodi log workflow"""

    def test_kodi_log(self):
        """Assert kodi_log correctly produces the expected events"""

        output = kodi_log(kodi_sample_log)

        df_lines = 0
        with open(kodi_sample_log, "r") as f:
            total_lines = len(f.readlines())

            for df_name, event_types in kodi_merge_events_dict.items():
                df = output[df_name]
                df_lines += df.shape[0]

                actual_event_types = sorted(df[event_type_column].unique().tolist())

                self.assertEqual(actual_event_types, sorted(set(event_types)))

        self.assertEqual(total_lines, df_lines)