import pandas as pd
from statsmodels.tsa.holtwinters import ExponentialSmoothing, HoltWintersResults


def holt_winters(
    training_series: pd.Series, season_offset: int, trend_type: str, seasonal_type: str
) -> HoltWintersResults:
    """
    This function fits a Holt-Winters model to given time series with the season length and trend and seasonality types.

    Parameters
    ---
    training_series : `pandas.Series`
        The time series to fit the Holt-Winters model.
    season_offset : `int`
        The season length of the time series.
    trend_type : `str`
        The trend type of the Holt-Winters model.
    seasonal_type : `str`
        The seasonal type of the Holt-Winters model.

    Return
    ---
    model : `statsmodels.tsa.holtwinters.HoltWintersResults`
        The fitted Holt-Winters model.
    """

    return ExponentialSmoothing(
        endog=training_series, trend=trend_type, seasonal=seasonal_type, seasonal_periods=season_offset
    ).fit()
