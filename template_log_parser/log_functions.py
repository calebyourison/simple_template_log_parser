import pandas as pd

from io import BytesIO, StringIO, TextIOBase
from pathlib import Path

from typing import Literal, Iterable, Union, Optional

from template_log_parser.definitions import (
    event_data_column,
    event_type_column,
    other_type_column,
    unparsed_text_column,
    SimpleTemplate,
)


def get_lines_from_file(
        f: Union[str, Path, BytesIO, StringIO, TextIOBase],
) -> list[str]:
    """Return a list of strings from a flat file

    :param f: Path to file or filelike object, most commonly in the format of some_log_process.log
    :type f: str, Path, BytesIO, StringIO, TextIOBase

    :return: list of string
    :rtype: list[str]

    :raise ValueError: If wrong file type is provided

    """
    if isinstance(f, (str, Path)):
        with open(f, "r", encoding="utf-8") as file_obj:
            return file_obj.read().splitlines()
    elif isinstance(f, BytesIO):
        f.seek(0)
        return f.read().decode("utf-8").splitlines()
    elif isinstance(f, (StringIO, TextIOBase)):
        f.seek(0)
        return f.read().splitlines()
    else:
        raise ValueError(
            "Unsupported file type. Must be str, Path, BytesIO, StringIO, or TextIOBase."
        )



def parse_function(event: str, templates: list[SimpleTemplate]) -> dict[str, str]:
    """Return a dictionary of information parsed from a log file string based on matching template.

    :param event: String data, should ideally match a repeated format throughout a text file
    :type event: str

    :param templates: formatted as a list of namedtuple (SimpleTemplate) [(compiled_template, event_type, search_string), ...]
    :type templates: list[SimpleTemplate]

    :return: dictionary containing:
        - event_type along parsed values if successful.  Otherwise, {"Unparsed_text": original_text, "event_type": "Other"}
    :rtype: dict[str, str]
    """
    for template_tuple in templates:
        if template_tuple.search_string not in event:
            continue

        parsed_result = template_tuple.template.parse(event)

        if parsed_result and len(parsed_result.named) == len(
            template_tuple.template.named_fields
        ):
            output = parsed_result.named
            output[event_type_column] = template_tuple.event_type
            return output

    return {unparsed_text_column: event, event_type_column: other_type_column}


def filter_line(
    line: str,
    match: str | list[str] | None = None,
    eliminate: str | list[str] | None = None,
    match_type: Literal["any", "all"] = "any",
    eliminate_type: Literal["any", "all"] = "any",
) -> bool:
    """Return True if log file line adheres to filter criteria

    Eliminate applied second, and therefore supersedes any words in match should conflicts exist.

    :param line: A single log file line
    :type line: str

    :param match: (optional) A single word or list of words must be present within the line otherwise dropped.
    :type match: str, List[str], None

    :param eliminate: (optional) A single word or a list of words if present within line will result in it being dropped
    :type eliminate: str, List[str], None

    :param match_type: (optional) criteria to determine if any words must be present to match, or all words
    :type match_type: Literal["any", "all"]

    :param eliminate_type: (optional) criteria to determine if any words must be present to eliminate, or all words
    :type eliminate_type: Literal["any", "all"]

    :return: True if string contains the match criteria and does not contain the eliminate criteria, else False
    :rtype: bool
    """

    def normalize(value: str | Iterable[str] | None) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(v) for v in value]

    def validate(items: list[str], log_line: str, mode: Literal["any", "all"]) -> bool:
        if mode == "all":
            return all(item in log_line for item in items)
        return any(item in log_line for item in items)

    match_items = normalize(match)
    eliminate_items = normalize(eliminate)

    # Return false if the match criteria is not met OR if the eliminate criteria is met
    if match_items and not validate(match_items, line, match_type):
        return False

    if eliminate_items and validate(eliminate_items, line, eliminate_type):
        return False

    return True


def log_pre_process(
    file: str | BytesIO | StringIO | TextIOBase,
    templates: list[SimpleTemplate],
    match: str | list[str] | None = None,
    eliminate: str | list[str] | None = None,
    match_type: Literal["any", "all"] = "any",
    eliminate_type: Literal["any", "all"] = "any",
) -> pd.DataFrame:
    """
    Return a Pandas DataFrame with named columns as specified by templates

    :param file: Path to file or filelike object, most commonly in the format of some_log_process.log
    :type file: str, Path, BytesIO, StringIO, TextIOBase

    :param templates: formatted as a list of namedtuple (SimpleTemplate) [(compiled_template, event_type, search_string), ...]
    :type templates: list[SimpleTemplate]

    :param match: (optional) A single word or list of words must be present within the line otherwise dropped.
    :type match: str, list[str], None

    :param eliminate: (optional) A single word or a list of words if present within line will result in it being dropped
    :type eliminate: str, list[str], None

    :param match_type: (optional) criteria to determine if any words must be present to match, or all words
    :type match_type: Literal["any", "all"]

    :param eliminate_type: (optional) criteria to determine if any words must be present to eliminate, or all words
    :type eliminate_type: Literal["any", "all"]

    :return: DataFrame with columns found in matching templates
    :rtype: Pandas.DataFrame

    :raise ValueError: If wrong file type is provided

    :note:
        eliminate applied second, and therefore supersedes any words in match should duplicate criteria exist.
    """
    parsed_results = []

    def parse_line(log_line: str) -> None:
        data = parse_function(log_line, templates)
        data[event_data_column] = log_line
        parsed_results.append(data)

    for line in get_lines_from_file(file):
        line = line.strip()
        if match or eliminate:
            valid_line = filter_line(
                line=line,
                match=match,
                eliminate=eliminate,
                match_type=match_type,
                eliminate_type=eliminate_type,
            )
            if valid_line:
                parse_line(line)

        else:
            parse_line(line)

    df = pd.DataFrame(parsed_results)

    return df


def process_log(
    file: str | BytesIO | StringIO | TextIOBase,
    templates: list[SimpleTemplate],
    dict_format: bool = True,
    datetime_columns: Optional[list[str]] = None,
    match: str | list[str] | None = None,
    eliminate: str | list[str] | None = None,
    match_type: Literal["any", "all"] = "any",
    eliminate_type: Literal["any", "all"] = "any",
) -> dict[str, pd.DataFrame] | pd.DataFrame:
    """Return a single Pandas Dataframe or dictionary of DataFrames whose keys are the log file event types,
    utilizing templates.

    :param file: Path to file or filelike object, most commonly in the format of some_log_process.log
    :type file: str, Path, BytesIO, StringIO, TextIOBase

    :param templates: formatted as a list of namedtuple (SimpleTemplate) [(compiled_template, event_type, search_string), ...]
    :type templates: list[SimpleTemplate]

    :param dict_format: Return a dictionary of DataFrames when True, one large DataFrame when False, True by default
    :type dict_format: (optional) bool

    :param datetime_columns: (optional) Columns to be converted using Pandas.to_datetime()
    :type datetime_columns: List[str]

    :param match: (optional) A single word or list of words must be present within the line otherwise dropped.
    :type match: str, List[str], None

    :param eliminate: (optional) A single word or a list of words if present within line will result in it being dropped
    :type eliminate: str, List[str], None

    :param match_type: (optional) criteria to determine if any words must be present to match, or all words
    :type match_type: Literal["any", "all"]

    :param eliminate_type: (optional) criteria to determine if any words must be present to eliminate, or all words
    :type eliminate_type: Literal["any", "all"]

    :return: dict formatted as {'event_type_1': df_1, 'event_type_2': df_2, ...}, Pandas Dataframe will include all event types and all columns
    :rtype: Dict[str, Pandas.DataFrame], Pandas Dataframe
    """

    # Initial parsing
    df = log_pre_process(
        file=file,
        templates=templates,
        match=match,
        eliminate=eliminate,
        match_type=match_type,
        eliminate_type=eliminate_type,
    )

    if datetime_columns:
        for col in datetime_columns:
            if col in df.columns:
                try:
                    df[col] = pd.to_datetime(df[col])
                except Exception as e:
                    print(f"Error converting column '{col}' to datetime: {e}")

    if not dict_format:
        return df
    else:
        if df.empty:
            return {}
        df_dict = {}
        # For every unique event_type create a copy df
        for event_type in df[event_type_column].unique().tolist():
            df_dict[event_type] = (
                df[df[event_type_column] == event_type].dropna(axis=1, how="all").copy()
            )
        return df_dict
