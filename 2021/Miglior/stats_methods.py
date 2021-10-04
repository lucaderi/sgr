# file containing simple and double exponential smoothing implementation
# in order to forecast on actual data.

def simple_exponential_smoothing(dataset, alpha) -> []:
    res = [dataset[0]]
    for n in range(1, len(dataset)):
        res.append(alpha * dataset[n] + (1 - alpha) * res[n-1])
    return res


def double_exponential_smoothing(dataset, alpha, beta) -> []:
    result = [dataset[0]]

    for n in range(1, len(dataset)):
        if n == 1:
            level, trend = dataset[0], dataset[1] - dataset[0]
        if n >= len(dataset):  # we are forecasting
            value = result[-1]
        else:
            value = dataset[n]

        last_level, level = level, alpha * value + (1 - alpha) * (level + trend)
        trend = beta * (level - last_level) + (1 - beta) * trend
        result.append(level + trend)

    return result
