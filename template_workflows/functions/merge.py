import pandas as pd
from template_log_parser.definitions import event_type_column, other_type_column

def merge_events(df:pd.DataFrame, merge_dictionary:dict[str, list[str]]) -> dict[str, pd.DataFrame]:
    """Return a dictionary of Pandas DataFrames whose keys are the event types, after merging specified event_types

    :param df: Dataframe of parsed data from process_log
    :type df: pd.DataFrame

    :param merge_dictionary: Formatted as {'new_df_name', ['event_type_1', 'event_type_2', ...], ...}
    :type merge_dictionary: dict

    :return: Dictionary of DataFrames formatted as {'new_df_name': new_df, 'event_type_3': df_3, ...}
    :rtype: dict
    """

    final_output = {}

    for df_name, event_types in merge_dictionary.items():
        event_df = df[df[event_type_column].isin(event_types)]
        event_df = event_df.dropna(axis=1, how="all")
        final_output[df_name] = event_df

    # Account for "Other"/ Unparsed Lines
    other_events = df[df[event_type_column] == other_type_column].dropna(axis=1, how="all")
    if not other_events.empty:
        final_output[other_type_column] = other_events

    return final_output