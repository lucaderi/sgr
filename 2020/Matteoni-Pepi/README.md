# APIForecast
The purpose of this project is to demonstrate the application of three main forecasting functions: single exponential smoothing, double exponential smoothing and Holt-Winters forecasting.

## Prerequisites
### Matplotlib
Install Matplotlib with `pip install matplotlib`
### NumPy
Install NumPy with `pip install numpy`
### PyShark
Install PyShark with `pip install pyshark`
### SciPy
Install SciPy with `pip install scipy`

## Description
The project consists of a few Python files:
 - **APIForecast.py**: here are implemented the three forecasting functions, along with SSE and RSI functions and two fitting functions. The fitting functions differs in the algorithm that they use: one uses the Nelder-Mead algorithm with some tweaks, and the other uses the TNC fitting algorithm from the SciPy package.
 - **Utils.py**: this files contains the plotting functions, which uses matplotlib, and a couple of utility functions for output formatting.
 - **CreateDatasets.py**: it implements the generation of the values datasets which we used for testing, with the options to create a "normal" dataset or an "anomalous" dataset. It also can produce a dataset from a pcap file.
 - Three demo scripts:
   - **Demo.py**: used to test the API by passing what we want to do via arguments on the CLI. It can read both json datasets and pcap files.
   - **DemoInteractive.py**: and interactive version of the previous script.
   - **Test.py**: an automatic test for Holt-Winters with default parameters.

## Usage
First, create a dataset with `python3 CreateDatasets.py --type series --days 5`

Then, we can use `Demo.py` to do a forecasting demo: `python3 Demo.py --dataset dataset.json --season 288 --rsi 24 --alpha 0.57300 --beta 0.00667 --gamma 0.92767`

Or we can use `Test.py` to do another forecasting demo: `python3 Test.py`
