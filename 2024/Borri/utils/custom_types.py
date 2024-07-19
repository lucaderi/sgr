import argparse
from datetime import timedelta

import pandas as pd


def percentage_type(value: str) -> float:
    """
    This function parses a string representing a percentage (between 0.5 and 1.0) and returns the corresponding float value.

    Parameters
    ---
    value : `str`
        A string representing a percentage.

    Return
    ---
    percentage : `float`
        A float value corresponding to the provided percentage.

    """

    value = float(value)

    if value < 0.5 or value > 1:
        raise argparse.ArgumentTypeError("Percentage must be between 0.5 and 1")

    return value


def timedelta_type(period: str) -> timedelta:
    """
    This function parses a string representing a period and returns the corresponing `datetime.timedelta` object.

    Parameters
    ---
    period : `str`
        A string representing a period according to the `pandas.Timedelta` formats.

    Return
    ---
    timedelta : `datetime.timedelta`
        A `datetime.timedelta` object corresponding to the provided period.

    """

    return pd.Timedelta(period).to_pytimedelta()
