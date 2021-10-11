import datetime as dt


class Candle:
    """
        Class representing a candle's instance.
        Candle type object has to be initialized with five values:
        @:param time  -> timestamp for the considered time window
        @:param open  -> first value of considered window
        @:param close -> last value of considered window
        @:param high  -> max value taken by the series inside the window
        @:param low   -> min value taken by the series inside the window

        time conversion from epoch to python datetime object is performed.
    """

    def __init__(self, time, open: float, close: float, high: float, low: float):
        self.time = time
        self.open = open
        self.close = close
        self.high = high
        self.low = low

    def __str__(self):
        return """Candle instance -> time: {}, open: {}, close: {}, max peak: {}, min peak: {}""".format(
            self.time,
            self.open,
            self.close,
            self.high,
            self.low
        )

    def to_dict(self):
        return {
            'date':  dt.datetime.fromtimestamp(self.time),
            'open':  self.open,
            'close': self.close,
            'high': self.high,
            'low': self.low,
            'volume': abs(self.open - self.close)
        }
