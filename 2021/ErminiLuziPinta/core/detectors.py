import math
from .forecasting import SingleExponentialSmoothing, DoubleExponentialSmoothing
import core.utils as utils
import curses
import time

class CusumDetector:
    """
    Parametric cumulative sum implementation for anomaly detection
    """

    def __init__(self, threshold, sigma=100000, alpha=0.5, window_size=3):
        self._detection_threshold = threshold

        # the gaussian's variance
        # intuitively indicates how much the new value is important in volume (self._test_statistics) computing
        self._sigma = sigma

        self._time_start = 0

        self._time_end = 0

        # maximum number of elements inside window
        self.__window_size = window_size
        # list of last self.__window_size elements
        self.__window = []

        # percentage beyond which the mean value (self.__mu) can be considered as anomalous behaviour
        self._alpha = alpha

        self._smoothing = SingleExponentialSmoothing()

        # the volume computed (used to check threshold excess)
        self._test_statistic = 0

        self._under_attack = False

        self._z = 0

        # once read self.__window_size values starts to apply cusum to new values
        self.__start_cusum = False

    def _data_smoothing(self, value: float):
        """
        Cumulative sum (CUSUM) implementation. \n
        Equation:
            - g_{n} = max( (g_{n-1} + (alpha*mu_{n-1} / sigma^{2}) * (x_{n} - mu_{n-1} - alpha*mu_{n-1}/2) , 0) \n
            - mu_{n} = beta*mu_{n-1} + (1- beta)*x_{n}
        where x_{n} is the metric (number of SYN packets) at interval n
        """

        if len(self.__window) < self.__window_size:
            # filling window

            self.__window.append(value)
            return

        elif len(self.__window) == self.__window_size and not self.__start_cusum:
            # first time that the window is full

            self.__window.append(value)
            self.__window = self.__window[1:]

            self._smoothing.initialize(self.__window)

            mean = self._smoothing.get_smoothed_value()

            # calculating simga value
            square_sum = 0
            for val in self.__window:
                square_sum += (val - mean) ** 2

            self.__start_cusum = True

        self.__window.append(value)
        self.__window = self.__window[1:]

        # calculating window mean
        window_mean = sum(self.__window) / self.__window_size

        # saving previous values of mu and sigma
        last_mu = self._smoothing.get_smoothed_value()

        self._smoothing.forecast(window_mean)

        alpha_times_mu = self._alpha * last_mu

        # calulating cusum value
        self._z = (alpha_times_mu / self._sigma) * (
                value - last_mu - alpha_times_mu / 2)

    def _cusum_detection(self):
        self._test_statistic = max(self._test_statistic + self._z, 0)

        if not self._under_attack:
            # checking violation
            if self._test_statistic > self._detection_threshold:
                utils.colors(0, 0, "Status: DoS attack detected", 197)
                self._test_statistic = 0
                self._time_start = time.time()
                self._under_attack = True

        else:
            if self._test_statistic <= self._detection_threshold:
                # violation not detected

                utils.colors(0, 0, "                                              ", 1)
                utils.colors(0, 0, "Status: DoS attack ended", 83)
                self._time_end = time.time()

                self._test_statistic = 0
                self._under_attack = False

    def update(self, value: float):
        self._data_smoothing(value)
        self._cusum_detection()

        return self._test_statistic

    def under_attack(self):
        """
        Tells if a DoS attack was detected

        :return: True if an attack was detected, False otherwise
        """

        return self._under_attack

    def get_time_start(self):
        return self._time_start

    def get_time_end(self):
        return self._time_end


class NPCusumDetector:
    """
    Non parametric cumulative sum implementation for anomaly detection
    """

    def __init__(self,
                 start_alarm_delay: int = 4,
                 stop_alarm_delay: int = 4,
                 window_size: int = 3,
                 outlier_threshold: float = 0.65,
                 ):

        self._time_start = 0

        self._time_end = 0
        # the volume computed (used to check threshold excess)
        self._test_statistic = 0

        self._under_attack = False

        # the attack detection threshold used by cusum algorithm
        self._detection_threshold = 0

        # a threshold for outlier identification
        self.__outlier_threshold = outlier_threshold

        # accumulates the threshold violations
        self.__outlier_cum = 0

        # time delay required for identifying the starting of an attack
        self.__start_alarm_delay = start_alarm_delay

        # maximum number of elements inside window
        self.__window_size = window_size
        # list of last self.__window_size elements
        self.__window = []

        # smoothing objects that implements the smoothing function
        self._smoothing = SingleExponentialSmoothing()

        # variance of values in window
        self._sigma = 0

        # once read self.__window_size values starts to apply cusum to new values
        self.__start_cusum = False

        # value used to calculate the test statistic
        self._z = 0

        # smoothing function for forecasting z values under attack
        self.__z_smoothing = DoubleExponentialSmoothing()

        # smoothing function for forecasting ewma values under attack
        self.__mu_smoothing = DoubleExponentialSmoothing()

        # saves last self.__stop_alarm_delay self._z values
        self.__z_values = []

        # saves last self.__stop_alarm_delay smoothed values
        self.__mu_values = []

        self.__start_ending_forecasting = False

        self.__start_abrupt_decrease_check = False

        # time delay required for identifying the ending of an attack
        self.__stop_alarm_delay = stop_alarm_delay

        # counts times that self.__z is negative after a certain time of attack detection
        self.__attack_ending_cum = 0

        # stores last value added in window
        self.__delta = -1

        # cumulates occurrences of abrupt decrease of next values stored in window
        self.__abrupt_decrease_cum = 0

        self.__alarm_dur = 0

        self.__smoothing_factor = 0

    def _outlier_processing(self, value: float) -> bool:

        if value > self.__outlier_threshold:
            # outlier threshold exceeded
            # the value is an outlier

            if not self._under_attack:
                # not already under attack

                self.__outlier_cum += 1

                if self.__outlier_cum == self.__start_alarm_delay:
                    # reached required times to detect an attack

                    utils.colors(0, 0, "Status: DoS attack detected", 197)
                    self._time_start = time.time()

                    self.__outlier_cum -= 1
                    self.__z_values.append(self._z)
                    self._under_attack = True
                    self.__alarm_dur += 1

            else:
                self.__alarm_dur += 1

            return True

        if self.__outlier_cum > 0:
            self.__outlier_cum -= 1

        return False

    def _data_smoothing(self, value: float):

        if len(self.__window) < self.__window_size:
            # filling window

            self.__window.append(value)
            return

        elif len(self.__window) == self.__window_size and not self.__start_cusum:
            # first time that the window is full

            self.__window.append(value)
            self.__window = self.__window[1:]

            self._smoothing.initialize(self.__window)
            self.__smoothing_factor = self._smoothing.get_smoothing_factor()

            mean = self._smoothing.get_smoothed_value()

            # calculating simga value
            square_sum = 0
            for val in self.__window:
                square_sum += (val - mean) ** 2

            self._sigma = math.sqrt(square_sum / self.__window_size)

            self.__start_cusum = True

            return

        self.__window.append(value)
        self.__window = self.__window[1:]

        # calculating window mean
        window_mean = sum(self.__window) / self.__window_size

        # saving previous values of mu and sigma
        last_mu = self._smoothing.get_smoothed_value()

        self._z = window_mean - last_mu - 3 * self._sigma

    def _update_values(self):

        # calculating window mean
        window_mean = sum(self.__window) / self.__window_size

        # saving previous values of mu and sigma
        last_mu = self._smoothing.get_smoothed_value()
        last_sigma_square = self._sigma ** 2

        # calculating window exponentially weighted moving average
        self._smoothing.forecast(window_mean)

        # calculating simga value
        self._sigma = math.sqrt(
            self.__smoothing_factor * last_sigma_square +
            (1 - self.__smoothing_factor) * (window_mean - last_mu) ** 2
        )

    def _cusum_detection(self):

        if not self.__start_cusum:
            return

        if not self._under_attack:

            self._test_statistic = max(self._test_statistic + self._z, 0)

            if self._z > 0:
                # adjusting detection threshold

                if self._detection_threshold == 0:
                    self._detection_threshold = self._z * self.__start_alarm_delay
                else:
                    self._detection_threshold = self._detection_threshold / 2 + \
                                                self._z * self.__start_alarm_delay / 2

                if self._test_statistic >= self._detection_threshold:
                    # under attack

                    utils.colors(0, 0, "Status: DoS attack detected", 197)
                    self._under_attack = True
                    self.__alarm_dur += 1
            else:
                self._update_values()

        else:
            # under attack

            # checking end of an attack throughout sign of self.__z

            if self.__alarm_dur < 6:
                self.__check_ending_with_z()
            else:
                self.__check_abrupt_decrease()

            self.__alarm_dur += 1

    def __check_ending_with_z(self):
        if self._z <= 0:
            self.__attack_ending_cum += 1

            if self.__attack_ending_cum == self.__stop_alarm_delay:
                # reached required time delay before detect an attack ending
                # detected end of attack
                utils.colors(0, 0, "                                              ", 1)
                utils.colors(0, 0, "Status: DoS attack ended", 83)
                self._time_end = time.time()

                self._under_attack = False
                self._test_statistic = 0
                self.__attack_ending_cum = 0
                self._detection_threshold = 0

                if self.__alarm_dur < 6:
                    self.__alarm_dur = 0

    def __check_abrupt_decrease(self):
        last_val = self.__window[-1]

        if self.__attack_ending_cum > 0:
            self.__attack_ending_cum -= 1

        # checking abrupt decrease of new values
        if self.__delta == -1:
            self.__delta = last_val
        else:
            if self.__delta - last_val >= (self.__delta - self._smoothing.get_smoothed_value())/2:
                # got abrupt decrease

                self.__abrupt_decrease_cum += 1

                if self.__abrupt_decrease_cum == self.__stop_alarm_delay:
                    # detected end of attack
                    utils.colors(0, 0, "                                              ", 1)
                    utils.colors(0, 0, "Status: DoS attack ended", 83)
                    self._time_end = time.time()

                    self._under_attack = False
                    self.__abrupt_decrease_cum = 0
                    self.__delta = -1
                    self._test_statistic = 0
                    self._detection_threshold = 0
            else:
                # updating self.__delta with exponentially weighted moving average method

                smoothing_factor = self._smoothing.get_smoothing_factor()
                self.__delta = smoothing_factor * self.__delta + (1 - smoothing_factor) * last_val

                if self.__abrupt_decrease_cum > 0:
                    self.__abrupt_decrease_cum -= 1

    def update(self, value: float):

        if not self._outlier_processing(value):

            self._data_smoothing(value)
            self._cusum_detection()

        return self._test_statistic

    def get_time_start(self):
        return self._time_start

    def get_time_end(self):
        return self._time_end

    def under_attack(self):
        """
        Tells if a DoS attack was detected

        :return: True if an attack was detected, False otherwise
        """

        return self._under_attack


class SYNNPCusumDetector(NPCusumDetector):
    def __init__(self, verbose=False):
        super(SYNNPCusumDetector, self).__init__()

        self.intervals = 0
        self._verbose = verbose

    def analyze(self, syn_count: int, synack_count: int):
        syn_value = 0.0

        if syn_count != 0:
            syn_value = float(syn_count - synack_count) / float(syn_count)

        syn_value = max(syn_value, 0)

        self.intervals += 1
        self.update(syn_value)

        utils.clean_line_end()
        utils.colors(1, 0,     "Interval number:     " + str(self.intervals), 8)
        utils.colors(2, 0,     "SYN volume:          " + str(self._test_statistic), 8)
        utils.colors(3, 0,     "SYN Threshold:       " + str(self._detection_threshold), 8)
        if self._verbose:
            utils.colors(4, 0, "SYN Value:           " + str(syn_value), 8)
            utils.colors(5, 0, "SYN Zeta:            " + str(self._z), 8)
            utils.colors(6, 0, "SYN Sigma:           " + str(self._sigma), 8)
            utils.colors(7, 0, "SYN Mu:              " + str(self._smoothing.get_smoothed_value()), 8)

        return self._test_statistic, self._detection_threshold


class SYNCusumDetector(CusumDetector):
    def __init__(self, threshold=0.65, verbose=False):
        super().__init__(threshold=threshold)
        self.intervals = 0
        self._verbose = verbose

    def analyze(self, syn_count: int, *args):
        self.intervals += 1
        self.update(syn_count)

        utils.clean_line_end()
        utils.colors(1, 0,     "Interval number:     " + str(self.intervals), 8)
        utils.colors(2, 0,     "SYN volume:          " + str(self._test_statistic), 8)
        utils.colors(3, 0,     "SYN Threshold:       " + str(self._detection_threshold), 8)
        if self._verbose:
            utils.colors(4, 0, "SYN Value:           " + str(syn_count), 8)
            utils.colors(5, 0, "SYN Zeta:            " + str(self._z), 8)
            utils.colors(6, 0, "SYN Sigma:           " + str(self._sigma), 8)
            utils.colors(7, 0, "SYN Mu:              " + str(self._smoothing.get_smoothed_value()), 8)

        return self._test_statistic, self._detection_threshold
