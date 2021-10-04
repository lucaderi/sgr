import datetime as dt


class Candle:
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
