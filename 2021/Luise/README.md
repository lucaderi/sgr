# **DEStracker** v0.1
## Intro
DEStracker is a simple script written in C to periodically read `/proc/net/dev` and keep track of the newtowrk usage via Double Exponential Smoothing, so to warn the user when an unusual value (usually a high spike of data) is read.

## Usage

This program uses nDPI's open source library, so make sure to have its folder in the following directory:

`/home/$$USER/nDPI-dev`

To install the program, simply type `make` inside the program's folder. Once installed, type `DEStrack` to start the program. Optional parameters are:

`DEStrack [sleepTime] [alpha] [beta] [yes/no]`

So for example, if you wanted a DES with high adaptability that loops every 5 seconds AND you wanted the program to print every step in the command line, you'd type

`DEStrack 5 0.9 0.9 yes`

Remember that a higher value for alpha and beta, which must be within 0 and 1, indicates higher adaptability to new data.

The program runs endlessly, so to stop it press Ctrl + C.
