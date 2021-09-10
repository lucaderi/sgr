import sys


# Function to calculate single exponential smoothing
def exponential_smoothing(data, alpha):
    result = [data[0]]
    for i in range(1, len(data)):
        result.append(alpha * data[i] + (1 - alpha) * result[i - 1])
    result.append(alpha * data[-1] + (1 - alpha) * result[-1])  # prediction
    return result


# Function to calculate double exponential smoothing
def double_exponential_smoothing(data, alpha, beta):
    result = [data[0]]
    for i in range(1, len(data) + 2):
        if i == 1:
            level, trend = data[0], data[1] - data[0]
        if i >= len(data):
            value = result[-1]  # prediction
        else:
            value = data[i]
        last_level = level
        level = alpha * value + (1 - alpha) * (level + trend)
        trend = beta * (level - last_level) + (1 - beta) * trend
        result.append(level + trend)
    return result


# Function to calculate sse
def sse(values, predictions):
    try:
        s = 0
        for n, r in zip(values, predictions):
            s = s + (n - r) ** 2
        return s
    except OverflowError:
        return sys.float_info.max
