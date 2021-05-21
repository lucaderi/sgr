# **DEStracker** v0.1
## Intro
DEStracker is a simple script written in C to periodically read `/proc/net/dev` and keep track of the network usage via Double Exponential Smoothing, so to warn the user when an unusual value (usually a high spike of data) is read.

## Installation

This program uses nDPI's open source library (you can download it at https://github.com/ntop/nDPI), so make sure to install it and have its folder in the following directory:

`/home/[UserName]/nDPI-dev`

To install the DEStracker, simply type `make` inside the program's folder. Once installed, type `DEStrack` to start the program.

## Usage

DEStracker will just print out a message at startup, and will run in the background waiting for an unusually high/low spike of data, to then warn the user if it ever finds one. There are 4 optional parameters to customize the program's behaviour:

`DEStrack [sleepTime] [alpha] [beta] [yes/no]`

`sleeptime` is an Integer that determines how often the program reads data;
`alpha` and `beta` are inputs for the Double Exponential Smoothing, adjusting respectively how fast it adapts to new data and how much does it take trend into consideration. Please note that they both must be between 0 and 1 (If unsure, leave these to 0.75). Lastly, `yes` is used to make the program print every reading it gets, even if no anomalies occur.

So for example, if you wanted a DES with high adaptability that loops every 5 seconds, and you wanted the program to print every step in the command line, you'd type

`DEStrack 5 0.85 0.85 yes`

The program runs endlessly, so to stop it press Ctrl + C.
