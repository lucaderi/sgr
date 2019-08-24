#include <ndpiReader.c>

int ndpi_wrap_get_api_version(){
	return NDPI_API_VERSION;
}

int ndpi_wrap_ndpi_num_fds_bits(){
	return NDPI_NUM_FDS_BITS;
}

int ndpi_wrap_num_custom_categories(){
	return NUM_CUSTOM_CATEGORIES;
}

int ndpi_wrap_custom_category_label_len(){
	return CUSTOM_CATEGORY_LABEL_LEN;
}

int ndpi_wrap_ndpi_max_supported_protocols(){
	return NDPI_MAX_SUPPORTED_PROTOCOLS;
}

int ndpi_wrap_ndpi_max_num_custom_protocols(){
	return NDPI_MAX_NUM_CUSTOM_PROTOCOLS;
}

int ndpi_wrap_ndpi_procol_size(){
	return NDPI_PROTOCOL_SIZE;
}

int ndpi_wrap_idle_scan_budget(){
	return IDLE_SCAN_BUDGET;
}

struct reader_thread* execute(int argc, char** argv, struct ndpi_detection_module_struct * replace, struct timeval time){
	int i = 0;
	startup_time = time;
	ndpi_info_mod = replace;
	memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));

    parseOptions(argc, argv);

    if((!json_flag) && (!quiet_mode)) {

      printf("Using nDPI (%s) [%d thread(s)]\n", ndpi_revision(), num_threads);
    }

    signal(SIGINT, sigproc);

    for(i=0; i<num_loops; i++)
      test_lib();
    if(results_path)  free(results_path);
    if(results_file)  fclose(results_file);
    if(extcap_dumper) pcap_dump_close(extcap_dumper);

    return ndpi_thread_info;
}

void free_detection_module_struct(struct ndpi_detection_module_struct * replace){
	ndpi_info_mod = replace;
	if(ndpi_info_mod) ndpi_exit_detection_module(ndpi_info_mod);
}