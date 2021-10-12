#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

//structure that contains parameters for the algorithm
struct ndpi_cusum_struct {

    //fixed parameters
    double dev_std;
    double mean;
    double k;

    //values calculated for the next iterations
    double cusum_plus;
    double cusum_minus;

    //the upper/lower limit on which the value should fall is not an anomaly
    double upper;
    double lower;

    //number of values read
    int value_read;

    //number of values used by algorithm
    int dim_window;

    //array for read values
    double *values_window;
};

int ndpi_cusum_init(struct ndpi_cusum_struct *cusum, double v[], int size, double deviation);

int ndpi_cusum_add_value(struct ndpi_cusum_struct *cusum, double _value, double *c_plus, double *c_minus);

double max(double a, double b);

int main() {
    struct ndpi_cusum_struct cusum;
    double v[] = {
        25.5,
        26,
        26.6,
        26.8,
        27.5,
        25.9,
        27,
        25.4,
        26.4,
        26.3,
        26.9,
        27.5,
        26.2,
        36.8,
        26.6
    };

    int i, num = sizeof(v) / sizeof(double);
    int size = 3;
    double dev_std = 0.8;
    int ret = ndpi_cusum_init(&cusum, v, size, dev_std);

    printf("Start Algorithm\n");

    for (int i = 0; i < num; ++i) {
        double c_plus, c_minus;

        int rc = ndpi_cusum_add_value(&cusum, v[i], &c_plus, &c_minus);

        printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t%.3f\n", i, v[i], c_plus, c_minus, cusum.lower, cusum.upper);

        //it checks if the prediction computed goes beyond a given fixed threshold
        if (c_plus > cusum.upper || c_minus < cusum.lower) printf("Attention: anomaly detected.\n");
    }

    return 0;
}

/*
  Cumulative Sum (CUSUM) Algorithm
*/

//it initializes the parameters passed to the algorithm
int ndpi_cusum_init(struct ndpi_cusum_struct *cusum, double v[], int size, double deviation) {
    
    memset(cusum, 0, sizeof(struct ndpi_cusum_struct));
    
    cusum->mean = 0;
    cusum->value_read = 0;
    cusum->dim_window = size;

    cusum->dev_std = deviation;

    cusum->k = cusum->dev_std / 2;

    cusum->upper = cusum->dev_std * 5;
    cusum->lower = (cusum->dev_std * -5);

    cusum->cusum_plus = 0;
    cusum->cusum_minus = 0;

    cusum->values_window = (double*)malloc(size * sizeof(double));

    return 0;
}

/*
   The CUSUM algorithm belongs to the family of change point detection algorithms that are based 
   on hypothesis testing; it involves a cumulative sum of a statistical data records added to some
   weights and when the sum exceeds a certain threshold an anomaly is detected.
   
   ci+ = max(0,ci+_1 + (Xi - Mu0) -k)
   ci- = max(0,ci-_1 - (Xi - Mu0) -k)
   
   Input:
    cusum            Datastructure previously initialized
    value            The value to add to the measurement
   
   Output:
    c_plus           The value of upper control limit
    c_minus          The value of lower control limit
   
   Return code:
    0                Too early: we don't have enough values. Output values are zero.
    1                Normal processing: forecast is meaningful

*/

int ndpi_cusum_add_value(struct ndpi_cusum_struct *cusum, double _value, double *c_plus, double *c_minus) {

    if (cusum->value_read < cusum->dim_window) {
        cusum->mean = cusum->mean + _value;

        //adds value to the structure
        cusum->values_window[cusum->value_read] = _value;
        cusum->value_read++;

        if (cusum->value_read == cusum->dim_window) cusum->mean = cusum->mean / cusum->dim_window;
        
        return 0;
    }

    //it calculates the mean
    cusum->mean = cusum->mean + ((_value - cusum->values_window[cusum->value_read % cusum->dim_window]) / cusum->dim_window);

    //adds value to the structure
    cusum->values_window[cusum->value_read % cusum->dim_window] = _value;
    cusum->value_read++;

    *c_plus = max(0, cusum->cusum_plus + (_value - cusum->mean) - cusum->k);
    *c_minus = max(0, cusum->cusum_minus - (_value - cusum->mean) - cusum->k);

    cusum->cusum_plus = *c_plus;
    cusum->cusum_minus = *c_minus;

    *c_minus = *c_minus * -1.0;

    return 1;
}

//function to calculate the maximum
double max (double a, double b) {
    if ( a > b)
        return a;
    else
        return b;
}
