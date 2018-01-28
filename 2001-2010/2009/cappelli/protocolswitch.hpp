/*
 * protocolswitch.hpp
 */

#ifndef PROTOCOLSWITCH_HPP_
#define PROTOCOLSWITCH_HPP_

#include <iostream>
#include <string.h>
#include "protocolswitch.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <sstream>
#include <boost/lexical_cast.hpp>
#include <netdb.h>

using namespace std;

string protIdtoName(int id);
string portToProtocoll(unsigned int porta);

#endif /* PROTOCOLSWITCH_HPP_ */
