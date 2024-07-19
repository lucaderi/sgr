#!/usr/bin/env python3

import argparse
import os
from datetime import timedelta

import matplotlib.dates as mdates
import matplotlib.pyplot as plt

from models.arima import arima
from models.holt_winters import holt_winters
from utils.custom_types import percentage_type, timedelta_type
from utils.rrd import rrd_fetch

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Forecast and anomaly detection with ARIMA or Holt-Winters models")
    parser.add_argument(
        "filename",
        type=str,
        help="input RRD file",
    )
    parser.add_argument(
        "model",
        type=str,
        choices=["arima", "holt_winters"],
        help="model to use",
    )
    parser.add_argument(
        "-s",
        "--start",
        type=str,
        default="end-30d",
        metavar="START",
        help="start time from which fetch data (parsed by rrdtool using the AT-STYLE format, with the addition of the keyword \"last\", which means the timestamp of the last observation in the file), default is 30 days before the last observation in the file",
    )
    parser.add_argument(
        "-e",
        "--end",
        type=str,
        default="last",
        metavar="END",
        help="end time until which fetch data (parsed the same way as the --start option), default is the last observation in the file",
    )
    parser.add_argument(
        "-i",
        "--step",
        type=timedelta_type,
        default=None,
        metavar="STEP",
        help="preferred interval between 2 data points (note: if specified the data may be downsampled)",
    )
    parser.add_argument(
        "-m",
        "--seasonal-period",
        type=timedelta_type,
        default=timedelta(days=1),
        metavar="SEAS_PERIOD",
        help="seasonal period (parsed by pandas.Timedelta, see https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.Timedelta.html for the available formats), default is 1 day",
    )
    parser.add_argument(
        "-f",
        "--forecast-period",
        type=timedelta_type,
        default=timedelta(days=7),
        metavar="FC_PERIOD",
        help="forecast period (parsed the same way as seasonal period), default is 7 day",
    )
    parser.add_argument(
        "-t",
        "--trend-type",
        type=str,
        default="add",
        choices=["add", "mul", "additive", "multiplicative"],
        help="trend type for the Holt-Winters method, default is additive",
    )
    parser.add_argument(
        "-l",
        "--seasonal-type",
        type=str,
        default="add",
        choices=["add", "mul", "additive", "multiplicative"],
        help="seasonal type for the Holt-Winters method, default is additive",
    )
    parser.add_argument(
        "-d",
        "--delta",
        type=float,
        default=1.5,
        metavar="DELTA",
        help="delta factor which defines the amplitude of the anomaly threshold, default is 1.5",
    )
    parser.add_argument(
        "-p",
        "--training-percentage",
        type=percentage_type,
        default=0.8,
        metavar="PERCENT",
        help="percentage of data to use for training, default is 80%% (the rest is used for computing RMSE)",
    )
    parser.add_argument(
        "-o",
        "--save-dir",
        type=str,
        metavar="DIR",
        help="directory where to save the forecasted data and anomalies points as a CSV file and the plots as PNG files",
    )
    parser.add_argument(
        "-q",
        "--hide-plots",
        action="store_true",
        help="do not show the graphs",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print the summary of the model",
    )

    args = parser.parse_args()
    start, end, step, data = rrd_fetch(filename=args.filename, start=args.start, end=args.end, step=args.step)

    season_offset = int(args.seasonal_period.total_seconds() // step.total_seconds()) if args.seasonal_period else 1
    forecast_offset = int(args.forecast_period.total_seconds() // step.total_seconds())

    if args.seasonal_period and season_offset < 2:
        parser.error(f"Seasonal period is too short since step is {step} and seasonal period is {args.seasonal_period}")
    elif args.seasonal_period and args.seasonal_period.total_seconds() % step.total_seconds() != 0:
        parser.error("Seasonal period is not a multiple of the step")

    if args.save_dir and not os.path.exists(args.save_dir):
        os.makedirs(args.save_dir)
    elif args.save_dir and not (os.path.isdir(args.save_dir) and os.access(args.save_dir, os.W_OK)):
        parser.error(f"Directory {args.save_dir} does not exist or is not writable")

    for source in data:
        series = data[source]

        nan_indexes = series.index[series.isna()]
        series = series.interpolate(method="time")

        training_size = int(len(series) * args.training_percentage)
        training_end = series.index[training_size]
        training_series = series[:training_size]
        test_series = series[training_size:]

        fit = (
            arima(training_series, season_offset)
            if args.model == "arima"
            else holt_winters(training_series, season_offset, args.trend_type, args.seasonal_type)
        )

        prediction = fit.predict(start=start, end=end + args.forecast_period - step)
        test_forecast = prediction[(training_end <= prediction.index) & (prediction.index < end)]
        forecast = prediction[prediction.index < end]

        errors = abs(series - forecast)
        errors_moving_mean = errors.rolling(window=season_offset, min_periods=1).mean()
        errors_moving_std = errors.rolling(window=season_offset, min_periods=1).std()

        lower_bound = forecast - errors_moving_mean - args.delta * errors_moving_std
        upper_bound = forecast + errors_moving_mean + args.delta * errors_moving_std
        anomaly_indexes = series.index[(series < lower_bound) | (series > upper_bound)]

        rmse = ((test_forecast - test_series) ** 2).mean() ** 0.5

        fig, ax = plt.subplots()
        ax.plot(series, color="black", label="Observed data")
        ax.plot(prediction, color="blue", linestyle="--", label=f"{args.model} forecast")
        ax.axvline(x=end - step, color="black", linestyle=":", label="Last observation")
        ax.axvline(x=training_end, color="black", linestyle=":", label="Training end")

        ax.plot(nan_indexes, series[nan_indexes], "o", color="black", label="Interpolated points")
        ax.plot(anomaly_indexes, series[anomaly_indexes], "o", color="red", label="Anomaly")

        ax.fill_between(
            series.index,
            lower_bound,
            upper_bound,
            color="orange",
            alpha=0.25,
            label="Anomaly threshold",
        )

        ax.set_xlabel("Time")
        ax.set_ylabel(source)
        ax.xaxis.set_major_formatter(mdates.ConciseDateFormatter(ax.xaxis.get_major_locator()))
        ax.legend(loc="best")
        fig.autofmt_xdate()

        if args.verbose:
            print(fit.summary(), "\n")

        print(f"RMSE over test set ({1-args.training_percentage:.0%} of data): {rmse}")
        print(f"{len(anomaly_indexes)} anomalies detected")

        for dt in anomaly_indexes:
            print(f"{source} anomaly detected at time {dt} with value {series[dt]}")

        if args.save_dir:
            filename = os.path.join(args.save_dir, f"{os.path.basename(args.filename)}-{source}-{args.model}")

            with open(f"{filename}.csv", "w", encoding="utf-8") as out:
                print("ds,timestamp,value", file=out)

                for dt in anomaly_indexes:
                    print(f"{source},{int(dt.timestamp())},ANOMALY", file=out)

                for dt, value in test_forecast.items():
                    print(f"{source},{int(dt.timestamp())},{value}", file=out)

            fig.set_size_inches(19.20, 10.80)
            fig.savefig(f"{filename}.png", dpi=100)

    if not args.hide_plots:
        plt.show()
