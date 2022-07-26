#include <getopt.h>
#include <math.h>
#include <rrd.h>
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_START			"now-1h"
#define DEFAULT_END				"now"
#define DEFAULT_THRESHOLD		100
#define DEFAULT_SIZE			20
#define DEFAULT_TRANSLATION		5

void help() {
	printf("Usage: skewness [-e <end>][-s <start>][-t <threshold>] -f <filename>\n"
		"-e <end>           RRD end time. Default %s\n"
		"-s <start>         RRD start time. Default %s\n"
		"-t <threshold>     Threshold to analyse skewness. Default %d\n"
		"-n <interval>      Size of interval of values to analyse. Default %d\n"
		"-T <translation>   Number of values to translate the interval. Default %d\n"
		"-f <rrd path>      Path of the RRD filename to analyze\n"
		,
		DEFAULT_END, DEFAULT_START, DEFAULT_THRESHOLD, DEFAULT_SIZE, DEFAULT_TRANSLATION);
	exit(0);
}


// compute skewness of given interval, long 'size' points, given interval mean 'mean'
double intervalSkewness(rrd_value_t interval[], int size, double mean) {

	double firstSum = 0.0, secondSum = 0.0;

	for(int i=0; i<size; i++) {
		firstSum += pow(interval[i]-mean, 3);
		secondSum += pow(interval[i]-mean, 2);
	}

	firstSum = firstSum/size;
	secondSum = (secondSum/size, 3);
	secondSum = sqrt(secondSum);
	double skewness = firstSum/secondSum;

	return skewness;
}


int main(int argc, char *argv[]) {

	char *start_s, *end_s, *filename = NULL, *cf, **names;
	rrd_time_value_t start_tv, end_tv;
	rrd_value_t *data, *p;
	time_t start, end;
	long step = 0, ds_cnt = 0;
	float threshold;
	int size, transl;

	start_s = DEFAULT_START;
	end_s = DEFAULT_END;
	cf = "AVERAGE";
	threshold = DEFAULT_THRESHOLD;
	size = DEFAULT_SIZE;
	transl = DEFAULT_TRANSLATION;

	int opt;
	while((opt = getopt(argc, argv, "s:e:t:n:T:f:h")) != -1) {
		switch(opt) {
			case 's':
				start_s = optarg;
				break;
			case 'e':
				end_s = optarg;
				break;
			case 't':
				threshold = atof(optarg);
				break;
			case 'n':
				size = atoi(optarg);
				break;
			case 'T':
				transl = atoi(optarg);
				break;
			case 'f':
				filename = optarg;
				break;
			case 'h':
				help();
				break;
			case '?':
			default:
				help();
				break;
		}
	}

	if(filename == NULL)
		help();

	if((rrd_parsetime(start_s, &start_tv) != NULL)) {
		printf("Unable to parse start time %s\n", start_s);
		return -1;
	}

	if((rrd_parsetime(end_s, &end_tv) != NULL)) {
		printf("Unable to parse end time %s\n", end_s);
		return -1;
	}

	rrd_proc_start_end(&start_tv, &end_tv, &start, &end);

	if(rrd_fetch_r(filename, cf, &start, &end, &step, &ds_cnt, &names, &data) != 0) {
		printf("Unable to extract data from rrd %s\n", filename);
		return -1;
	}

	p = data;
	rrd_value_t interval[size];

	double mean = 0;
	int i = 0, j = 0, s = 0;
	int already_skew = 0, t1old;

	// max and min skewness values within the given threshold
	double max, min;
	// max and min skewness values outside the given threshold
	double maxskew, minskew;

	printf("MIN/MAX\t\t\t\t\ttime interval\n\n");

	// fill 'interval' with values
	while(i < size) {
		rrd_value_t value = *p++;
		j++;

		if(!isnan(value)) {
			interval[i] = value;
			mean = ((mean*i) + value)/ (double)(i+1);
			i++;

			// compute skewness only every 'transl' values
			if((s % transl) == 0) {
				double skewness = intervalSkewness(interval, i, mean);

				if(i == 0) {
					min = skewness;
					max = skewness;
				}

				// print if its skewer than threshold
				if((skewness >= threshold || skewness <= -threshold) &&
						(skewness < 2*min || skewness > 2*max)) {

					if(already_skew) {
						//printf("%.5f\t", skewness);

						if(maxskew < skewness) maxskew = skewness;
						if(minskew > skewness) minskew = skewness;
					}
					else {
						t1old = j*step+start;
						//printf("%.5f\t", skewness);
						already_skew = 1;

						maxskew = skewness;
						minskew = skewness;
					}
				}
				else if(already_skew) {

					already_skew = 0;

					// print human readable time
					char buf1[32], buf2[32];

					const time_t _t2 = j+start+transl;
					struct tm *t_info = localtime((const time_t*)&_t2);
					strftime(buf2, sizeof(buf2), "%d/%b/%Y %H:%M:%S", t_info);

					const time_t _t1 = t1old;
					t_info = localtime((const time_t*)&_t1);
					strftime(buf1, sizeof(buf1), "%d/%b/%Y %H:%M:%S", t_info);

					printf("%5.f\t%5.f \t", minskew, maxskew);
					printf("%s - %s\n", buf1, buf2);

					if(max < skewness) max = skewness;
					if(min > skewness) min = skewness;
				} else {
					if(max < skewness) max = skewness;
					if(min > skewness) min = skewness;
				}
			}
			s++;
		}
	}

	s = 0;
	int index = 0, last_skew;

	for(int t=start+j*step+1; t<end; t+=step) {
		rrd_value_t value = *p++;

		if(!isnan(value)) {
			mean = (size*mean - interval[index] + value)/(double)size;
			interval[index] = value;
			index = (index+1) % size;

			// compute skewness only every 'transl' values
			if((s % transl) == 0) {
				double skewness = intervalSkewness(interval, size, mean);

				// print if its skewer than threshold
				if((skewness >= threshold || skewness <= -threshold) &&
						(skewness < 2*min || skewness > 2*max)) {

					if(already_skew) {
						//printf("%.5f\t", skewness);

						if(maxskew < skewness) maxskew = skewness;
						if(minskew > skewness) minskew = skewness;
					}
					else {
						t1old = t-transl;
						//printf("%.5f\t", skewness);
						already_skew = 1;

						maxskew = skewness;
						minskew = skewness;
					}
					last_skew = t;
				}
				else if(already_skew) {

					already_skew = 0;

					// print human readable time
					char buf1[32], buf2[32];

					const time_t _t2 = t;
					struct tm *t_info = localtime((const time_t*)&_t2);
					strftime(buf2, sizeof(buf2), "%d/%b/%Y %H:%M:%S", t_info);

					const time_t _t1 = t1old;
					t_info = localtime((const time_t*)&_t1);
					strftime(buf1, sizeof(buf1), "%d/%b/%Y %H:%M:%S", t_info);

					printf("%5.f\t%5.f \t", minskew, maxskew);
					printf("%s - %s\n", buf1, buf2);

					if(max < skewness) max = skewness;
					if(min > skewness) min = skewness;
				} else {
					if(max < skewness) max = skewness;
					if(min > skewness) min = skewness;
				}

			}
			s++;
		}
	}

	if(already_skew) {
		char buf1[32], buf2[32];

		const time_t _t2 = last_skew;
		struct tm *t_info = localtime((const time_t*)&_t2);
		strftime(buf2, sizeof(buf2), "%d/%b/%Y %H:%M:%S", t_info);

		const time_t _t1 = t1old;
		t_info = localtime((const time_t*)&_t1);
		strftime(buf1, sizeof(buf1), "%d/%b/%Y %H:%M:%S", t_info);

		printf("%5.f\t%5.f \t", minskew, maxskew);
		printf("%s - %s\n", buf1, buf2);
	}

	rrd_freemem(data);
	return 0;
}
