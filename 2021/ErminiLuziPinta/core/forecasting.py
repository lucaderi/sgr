from scipy import optimize
import random
import sys
import numpy as np
import core.utils as utils


class ExponentialSmoothing:

    def initialize(self, training_values: list):
        """
        Initializes smoothed value to given value for next iterations.

        :param training_values: the values used to estimate forecasting factors
        """

        pass

    def get_smoothed_value(self) -> float:
        """
        Returns the calculated smoothed value
        """

        pass

    def get_smoothing_factor(self) -> float:
        """
        Returns the estimated smoothing factor
        """

        pass

    def forecast(self, value: float) -> float:
        """
        Applies exponential smoothing algorithm
        to forecast next value from given value and previous values

        :param value: the new value to do forecasting
        :return: forecasted value
        """

        pass

    def forecast_for(self, intervals: int) -> list:
        """
        Forecasts for specified number of intervals without changing internal state

        :param intervals: number of intervals to forecast
        :return: list containing the forecasted values
        """

        pass


class SingleExponentialSmoothing(ExponentialSmoothing):

    def __init__(self, initial_smoothed_value=0, smoothing_factor=0):

        self.__bounds = (
            (0.95, 0.99),  # smoothing factor value bounds
        )

        self.__smoothing_factor = smoothing_factor

        self.__smoothed_value = initial_smoothed_value

    def __sse(self, values, smoothing_factor):

        self.__smoothing_factor = smoothing_factor

        predictions = [values[0]]

        for value in values[1:]:
            predictions.append(self.forecast(value))

        try:
            s = 0
            for n, r in zip(values, predictions):
                s = s + (n - r) ** 2

            return s
        
        except OverflowError:
            return sys.float_info.max

    def initialize(self, training_values):

        self.__smoothing_factor = random.uniform(self.__bounds[0][0], self.__bounds[0][1])

        # initializing smoothed value
        self.__smoothed_value = sum(training_values) / len(training_values)

        forecasting_factors_init_guess = np.array([self.__smoothing_factor])

        loss_function = lambda x: self.__sse(training_values, x[0])

        forecasting_factors = optimize.minimize(
            loss_function,
            forecasting_factors_init_guess,
            method="SLSQP",
            bounds=self.__bounds
        )

        self.__smoothing_factor = forecasting_factors.x[0]
        utils.colors(1,50,"Data SES Smoothing factor:     " + str(self.__smoothing_factor),8)

    def get_smoothed_value(self) -> float:
        return self.__smoothed_value

    def get_smoothing_factor(self) -> float:
        return self.__smoothing_factor

    def forecast(self, value: float) -> float:
        self.__smoothed_value = self.__smoothing_factor * self.__smoothed_value + (1 - self.__smoothing_factor) * value

        return self.__smoothed_value

    def forecast_for(self, intervals: int) -> list:
        smoothing = SingleExponentialSmoothing(self.__smoothed_value, self.__smoothing_factor)

        forecasted_values = [smoothing.forecast(self.__smoothed_value)]

        for i in range(intervals-1):
            forecasted_values.append(smoothing.forecast(forecasted_values[-1]))

        return forecasted_values


class DoubleExponentialSmoothing(ExponentialSmoothing):

    def __init__(self, initial_smoothed_value=0, initial_trend_value=0, smoothing_factor=0, trend_factor=0):

        self.__bounds = (
            (0.95, 0.99),  # smoothing factor value bounds
            (0, 1)      # trend factor value bounds
        )

        self.__smoothing_factor = smoothing_factor
        self.__trend_factor = trend_factor

        self.__smoothed_value = initial_smoothed_value
        self.__trend_value = initial_trend_value

    def __sse(self, values, smoothing_factor, trend_factor):

        self.__smoothing_factor = smoothing_factor
        self.__trend_factor = trend_factor

        predictions = [values[0]]

        for value in values[1:]:
            predictions.append(self.forecast(value))

        try:
            s = 0
            for n, r in zip(values, predictions):
                s = s + (n - r) ** 2
            return s
        except OverflowError:
            return sys.float_info.max

    def initialize(self, training_values: list):
        self.__smoothing_factor = random.uniform(self.__bounds[0][0], self.__bounds[0][1])
        self.__trend_factor = random.uniform(self.__bounds[1][0], self.__bounds[1][1])

        # initializing smoothed value
        self.__smoothed_value = sum(training_values) / len(training_values)

        # initializing trend value
        self.__trend_value = (training_values[-1] - training_values[0]) / (len(training_values)-1)

        forecasting_factors_init_guess = np.array([self.__smoothing_factor, self.__trend_factor])

        loss_function = lambda x: self.__sse(training_values, x[0], x[1])

        forecasting_factors = optimize.minimize(
            loss_function,
            forecasting_factors_init_guess,
            method="SLSQP",
            bounds=self.__bounds
        )

        self.__smoothing_factor = forecasting_factors.x[0]
        self.__trend_factor = forecasting_factors.x[1]

        utils.colors(2,50,"CUSUM DES Smoothing factor:     " + str(self.__smoothing_factor),8)
        utils.colors(3,50,"CUSUM DES Trend factor:         " + str(self.__trend_factor),8)

    def get_smoothed_value(self) -> float:
        return self.__smoothed_value + self.__trend_value

    def get_smoothing_factor(self) -> float:
        return self.__smoothing_factor

    def forecast(self, value: float) -> float:
        last_smoothed_value = self.__smoothed_value
        self.__smoothed_value = self.__smoothing_factor * value + \
                                (1 - self.__smoothing_factor) * (self.__smoothed_value + self.__trend_value)

        self.__trend_value = self.__trend_factor * (self.__smoothed_value - last_smoothed_value) + \
                             (1 - self.__trend_factor) * self.__trend_value

        return self.__smoothed_value + self.__trend_value

    def forecast_for(self, intervals: int) -> list:
        smoothing = DoubleExponentialSmoothing(
            self.__smoothed_value,
            self.__trend_value,
            self.__smoothing_factor,
            self.__trend_factor
        )

        forecasted_values = [smoothing.forecast(self.__smoothed_value+self.__trend_value)]

        for i in range(intervals-1):
            forecasted_values.append(smoothing.forecast(forecasted_values[-1]))

        return forecasted_values
