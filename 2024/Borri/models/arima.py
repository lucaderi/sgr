import os
from datetime import datetime

import pandas as pd
from statsforecast import StatsForecast
from statsforecast.models import AutoARIMA
from statsmodels.tsa.arima.model import ARIMA, ARIMAResults

os.environ["NIXTLA_ID_AS_COL"] = "1"


def arima(training_series: pd.Series, season_offset: int) -> ARIMAResults:
    """
    This function fits an ARIMA model to given time series with the specified season length.

    Parameters
    ---
    training_series : `pandas.Series`
        The time series to fit the ARIMA model.
    season_offset : `int`
        The season length of the time series.

    Return
    ---
    model : `statsmodels.tsa.arima.model.ARIMAResults`
        The fitted ARIMA model.
    """
    datestamps = [dt.astype(datetime) for dt in training_series.index.values]
    df = pd.DataFrame({"ds": datestamps, "y": training_series.values, "unique_id": 1})
    sf = StatsForecast(
        models=[AutoARIMA(season_length=season_offset) if season_offset > 1 else AutoARIMA()],
        freq=int(pd.to_timedelta(training_series.index.freq).total_seconds()),
        n_jobs=-1,
    ).fit(df=df)

    params = tuple(sf.fitted_[0, 0].model_["arma"][i] for i in [0, 5, 1, 2, 6, 3, 4])
    order = params[:3]
    seasonal_order = params[3:6]
    season_offset = params[6]

    return (
        ARIMA(training_series, order=order, seasonal_order=seasonal_order + (season_offset,)).fit()
        if season_offset > 1 and sum(seasonal_order) > 0
        else ARIMA(training_series, order=order).fit()
    )
