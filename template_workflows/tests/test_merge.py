import unittest
import pandas as pd
from pandas._testing import assert_frame_equal


from template_workflows.functions.merge import merge_events
from template_log_parser.definitions import event_type_column, other_type_column

class TestMerge(unittest.TestCase):
    """Defines a class to test the merge module"""

    def test_merge_events(self):
        """Assert merge_events returns the correct columns per DataFrame"""
        merge_dict = {
            "letters": ["a", "b", "c"],
            "numbers": ["1", "2", "3"],
            "other": ["this", "that", "other"],
            "not_present": ["not", "present"]
        }

        data = {
            event_type_column: ["a", "b", "c", "1", "2", "3", "this", "that", "other", "Other"],
            "data_1": [1,2,3, pd.NA, pd.NA, pd.NA, pd.NA, pd.NA, pd.NA, 100],
            "data_2": [1,2,3, pd.NA, pd.NA, pd.NA, 7, 8, 9, 100],
            "data_3": [1,2,3, 4, 5, 6, pd.NA, pd.NA, pd.NA, 100]
        }

        df = pd.DataFrame(data)

        merged = merge_events(df.copy(), merge_dict)

        self.assertTrue(merged["not_present"].empty)

        letters = merged["letters"]
        self.assertEqual(sorted(letters[event_type_column].unique()), sorted(merge_dict.get("letters", [])))
        self.assertEqual(sorted(letters.columns), sorted([event_type_column, "data_1", "data_2", "data_3"]))

        numbers = merged["numbers"]
        self.assertEqual(sorted(numbers[event_type_column].unique()), sorted(merge_dict.get("numbers", [])))
        self.assertEqual(sorted(numbers.columns), sorted([event_type_column, "data_3"]))

        other = merged["other"]
        self.assertEqual(sorted(other[event_type_column].unique()), sorted(merge_dict.get("other", [])))
        self.assertEqual(sorted(other.columns), sorted([event_type_column, "data_2"]))

        unparsed = merged[other_type_column]
        self.assertEqual(sorted(unparsed[event_type_column].unique()), [other_type_column])
        self.assertEqual(sorted(unparsed.columns), sorted([event_type_column, "data_1", "data_2", "data_3"]))

        dfs = []
        for item in merged.values():
            dfs.append(item)

        re_merged:pd.DataFrame = pd.concat(dfs)

        re_merged = re_merged.fillna(pd.NA)

        assert_frame_equal(re_merged, df)

