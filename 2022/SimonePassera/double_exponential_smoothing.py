#!/usr/bin/python3.7

import sys
import statistics as stat
import math

# Smoothing factor
alpha = 0.9
# Trend factor
beta = 0.9
# Factor that determines the probability of the confidence interval, es: z=3.291 => Conf. Interval=99.9% 
z = 3.291

# Return the forecast of the next temperature value
def double_exponential_smoothing(series, alpha, beta):
    result = [series[0]]
    
    for n in range(1, len(series)+1):
        if n == 1:
            level, trend = series[0], series[1] - series[0]
        if n >= len(series): # we are forecasting
            value = result[-1]
        else:
            value = series[n]

        last_level, level = level, alpha*value + (1-alpha)*(level+trend)
        trend = beta*(level-last_level) + (1-beta)*trend
        result.append(level+trend)

    return round(result[-1], 1)

# Contains the temperature values in argv multiplied by 10 and rounded to the first decimal place
series = []

for i in range(1, len(sys.argv)):
    series.append(round(float(sys.argv[i]) * 10.0, 1))

prediction = double_exponential_smoothing(series, alpha, beta)

confidence = z * (stat.stdev(series) / math.sqrt(len(series)))
upper_bound = round(prediction + confidence, 1)
lower_bound = round(prediction - confidence, 1)

print(str(lower_bound) + " " + str(prediction) + " " + str(upper_bound))
