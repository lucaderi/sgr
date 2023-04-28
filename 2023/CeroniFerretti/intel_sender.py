from pyintelowl import IntelOwl, IntelOwlClientException
import configparser

def intelTest(ip):
	try:
		a = client.send_observable_analysis_request(ip, analyzers_requested=["Pulsedive"], observable_classification="ip")
		job_id = a['job_id']
		return job_id
	except IntelOwlClientException as e:
		print("Oh no! Error: ", e)

def status(job_id):
	job = client.get_job_by_id(job_id)
	if job['status']=='reported_without_fails':
		return True
	else:
		return False

def workJob(job_id):
	job = client.get_job_by_id(job_id)
	risk = job['analyzer_reports']
	element = risk[0]
	rk = element['report']['risk']
	print(rk,job_id)
	if rk=='medium' or rk=='high':
		return True
	else:
		client.delete_job_by_id(job_id)
		print("falso allarme")
		return False


config = configparser.ConfigParser()
config.read('pane_config.ini')
key_value = config.get('Key', 'Key')
url_value = config.get('Url','URL')

client = IntelOwl(key_value, url_value, None)