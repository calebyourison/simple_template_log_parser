import unittest

from test.resources import logger, built_in_log_file_types

from template_log_parser.templates.template_functions import compile_templates


class TestLogTypeClasses(unittest.TestCase):
    """Defines a class for tests of LogTypeClasses themselves"""

    def test_modify_templates(self):
        """Test function to determine that modify templates correctly adds prefixes and/or suffixes"""
        logger.info(f"---Checking modify_templates()")
        splitting_item = "-|-|-|-|"
        prefix_base = "Line Start "
        prefix = prefix_base + splitting_item
        suffix_base = " Line End"
        suffix = splitting_item + suffix_base

        for built_in in built_in_log_file_types:
            logger.info(f'Built-In {built_in.name}')
            built_in.modify_templates(prefix=prefix, suffix=suffix)

            pairs = zip(built_in.templates, built_in.base_templates)

            for (modified_template, base_template) in pairs:
                modified_compiled_template = modified_template.template.format
                logger.debug(f'Modified template: {modified_template}')
                parts = modified_compiled_template.split(splitting_item)

                self.assertEqual(parts[0], prefix_base)
                logger.debug(f"Actual prefix: ({parts[0]}), expected: ({prefix_base})")
                self.assertEqual(parts[1], base_template[0])
                logger.debug(f"Modified template string split from prefix/suffix ({parts[1]}) equals base template: ({base_template[0]})")
                self.assertEqual(parts[2], suffix_base)
                logger.debug(f"Actual suffix: ({parts[2]}), expected: ({suffix_base})")

                self.assertEqual(modified_template[1], base_template[1])
                logger.debug(f"Actual event type: ({modified_template[1]}) expected ({base_template[1]})")

                # If base template had search string, it should match
                if len(base_template) == 3:
                    expected_search_string = base_template[2]

                # If base template had no search string, it should equal event_type per 'copy'
                else:
                    expected_search_string = base_template[1]

                self.assertEqual(modified_template[2], expected_search_string)
                logger.debug(f"Actual search_string: ({modified_template[2]}), expected: ({expected_search_string})")

        logger.info('OK')



        logger.info("All templates accounted for")

        # Set all templates back to normal
        for built_in in built_in_log_file_types:
            built_in.templates = compile_templates(built_in.base_templates, search_string_criteria='copy')





