################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../prova.o 

CPP_SRCS += \
../main.cpp \
../prova.cpp \
../test_pcap.cpp 

OBJS += \
./main.o \
./prova.o \
./test_pcap.o 

CPP_DEPS += \
./main.d \
./prova.d \
./test_pcap.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -I/home/francesco/Scrivania/mc-fastflow -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


