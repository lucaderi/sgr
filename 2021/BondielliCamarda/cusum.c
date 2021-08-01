#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

//structure that contains parameters for the algorithm
struct ndpi_cusum_struct {
    
    //fixed parameters
    struct {
        double alpha, beta, sigma;
        //maximum number of elements inside window
        int window_size;
    } params;

    //array for read values
    double *values_window;

    //number of read values by the algorithm
    u_int32_t num_values;
    
    //values calculated for the next iterations
    double last_forecast, last_mu, square_sigma, mean;

    //indicates if the algorithm has started
    bool start_cusum;
};

int ndpi_cusum_init(struct ndpi_cusum_struct *cusum, double alpha, double beta, double sigma, int window_size);

int ndpi_cusum_add_value(struct ndpi_cusum_struct *cusum, const u_int64_t _value, double *forecast);

double max(double a, double b);

int main() {
    struct ndpi_cusum_struct cusum;
    double v[] = {
        31.908466339111,
        87.339714050293,
        173.47660827637,
        213.92568969727,
        223.32124328613,
        230.60134887695,
        238.09457397461,
        245.8137512207,
        251.09228515625,
        251.09228515625,
        259.21997070312,
        261.98754882812,
        264.78540039062,
        264.78540039062,
        270.47451782227,
        173.3671875,
        288.34222412109,
        288.34222412109,
        304.24795532227,
        304.24795532227,
        350.92227172852,
        384.54431152344,
        423.25942993164,
        439.43322753906,
        445.05981445312,
        445.05981445312,
        445.05981445312,
        445.05981445312
    };

    int i, num = sizeof(v) / sizeof(double);
    double alpha = 0.5, sigma = 10, beta = 0.95;

    int ret = ndpi_cusum_init(&cusum, alpha, beta, sigma, 3);

    printf("Start Algorithm\n");

    for (int i = 0; i < num; ++i) {
        double prediction, threshold = 1500;
        int rc = ndpi_cusum_add_value(&cusum, v[i], &prediction);

        //it checks if the prediction computed goes beyond a given fixed threshold
        if (prediction > threshold) printf("Attention: anomaly detected.\n");

        printf("%2u)\t%12.3f\t%.3f\n",i, v[i], prediction);
    }

    return 0;
}

/*
  Cumulative Sum (CUSUM) Algorithm
*/

//it initializes the parameters passed to the algorithm
int ndpi_cusum_init(struct ndpi_cusum_struct *cusum, double alpha, double beta, double sigma, int window_size) {
    
    memset(cusum, 0, sizeof(struct ndpi_cusum_struct));

    cusum->params.alpha = alpha;
    cusum->params.beta = beta;

    cusum->params.sigma = sigma;
    cusum->square_sigma = sigma * sigma;

    cusum->params.window_size = window_size;

    cusum->num_values = 0;
    cusum->last_forecast = 0;
    cusum->mean = 0;

    cusum->values_window = (double*)malloc(cusum->params.window_size * sizeof(double));

    cusum->start_cusum = false;

    return(0);
}

/*
   The CUSUM algorithm belongs to the family of change point detection algorithms that are based 
   on hypothesis testing; it involves a cumulative sum of a statistical data records added to some
   weights and when the sum exceeds a certain threshold an anomaly is detected.
   
   z_{n} = max( (z_{n-1} + (alpha*mu_{n-1} / sigma^{2}) * (x_{n} - mu_{n-1} - alpha*mu_{n-1}/2) , 0)
   mu_{n} = beta*mu_{n-1} + (1- beta)*x_{n}
   
   Input:
    cusum            Datastructure previously initialized
    value            The value to add to the measurement
   
   Output:
    forecast         The forecasted value
   
   Return code:
    0                Too early: we don't have enough values. Output values are zero.
    1                Normal processing: forecast is meaningful
*/

int ndpi_cusum_add_value(struct ndpi_cusum_struct *cusum, const u_int64_t _value, double *forecast) {
    double value = (double)_value;
    double z;
    double mean_window;
    double mu;
    double alpha_mu;

    //it checks if the algorithm has started or not
    if (!cusum->start_cusum) {
        if (cusum->num_values < cusum->params.window_size) { //algorithm not yet started
            
            //adds value to the structure
            cusum->values_window[cusum->num_values] = value;

            //adds value to the counter for the mean
            cusum->mean += value;

            z = 0;
            cusum->num_values++;
            *forecast = max(cusum->last_forecast + z, 0);

            return 0;
        } 
        else { //cusum->num_values = cusum->params.window_size

            z = 0;

            //it contains the sum of values in the structure
            cusum->mean -= cusum->values_window[cusum->num_values % cusum->params.window_size];

            //adds value to the structure
            cusum->values_window[cusum->num_values % cusum->params.window_size] = value;

            //last_mu = mean
            cusum->mean = (cusum->mean + value) / cusum->params.window_size;
            cusum->last_mu = cusum->mean;

            cusum->num_values++;
            *forecast = max(cusum->last_forecast + z, 0);
            cusum->start_cusum = true;

            return 0;
        }
    } 
    else { //start algorithm
        
        mean_window = cusum->mean + ((value - cusum->values_window[cusum->num_values % cusum->params.window_size]) / cusum->params.window_size);
        cusum->mean = mean_window;

        //adds value to the structure
        cusum->values_window[cusum->num_values % cusum->params.window_size] = value;

        //it calculates mu = beta*mu_1 + (1-beta)*media
        mu = (cusum->params.beta * cusum->last_mu) + ((1 - cusum->params.beta) * mean_window);

        alpha_mu = cusum->params.alpha * cusum->last_mu;

        //it calculates z = (alfa*mu/sigma^2) * (value-mu_1-(alfa*mu/2))
        z = (alpha_mu / cusum->square_sigma) * (value - cusum->last_mu - (alpha_mu/2));

        *forecast = max(cusum->last_forecast + z, 0);
    
        cusum->num_values++;
        cusum->last_mu = mu;
        cusum->last_forecast = *forecast;

        return 1;
    }
}

//function to calculate the maximum
double max (double a, double b) {
    if ( a > b)
        return a;
    else
        return b;
}
