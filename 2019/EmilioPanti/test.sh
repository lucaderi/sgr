#!/bin/bash
# This script creates a pod test (which simply pinges) and captures the packages (30 seconds) via podsniffer.sh
# Pre-condition:
#   - presence of an active kubernetes node (tested on minikube node)
#   - the capture script (podsniffer.sh) must be in the same directory as this script


noww=$(date +%s)
podtestjob="pod-test-job-${noww}"
snifferscript="./podsniffer.sh"  

if [ -x "/snap/bin/microk8s.kubectl" ]; then
    kubectl="/snap/bin/microk8s.kubectl"
else 
    kubectl=$(which kubectl)
fi


#check the preconditions
if ! [ -e "${snifferscript}" ]; then
    echo "Error: ${snifferscript} not present in ${PWD}"
    echo ""
    exit 1
fi


#start the test pod
echo "Creating the test pod..."
cat << EOF > podtestjob.yaml
  apiVersion: batch/v1
  kind: Job
  metadata:
    name: ${podtestjob}
  spec:
    template:
      metadata:
        name: pod-test-pod
      spec:
        hostNetwork: true
        containers:
        - name: pod-test
          image: "docker.io/centos"
          command: ["/bin/bash", "-c", "--"]
          args: [ "ping spotify.com" ]
        restartPolicy: Never 
EOF

${kubectl} apply -f podtestjob.yaml > /dev/null 2>&1
rm podtestjob.yaml

podtest=$(${kubectl} get pods --selector=job-name=${podtestjob} --output=jsonpath='{.items[*].metadata.name}')
if [[ $? -ne 0 ]];then
    ${kubectl} delete jobs/${podtestjob} > /dev/null 2>&1
    echo "Error: test job has not started"
    echo ""
    exit 1
fi

sleep 3

status=$(${kubectl} get pod ${podtest} --output=jsonpath='{.status.phase}')
if [[ "${status}" = "Failed" ]];then
    ${kubectl} delete jobs/${podtestjob} > /dev/null 2>&1
    echo "Error: test job has not started correctly"
    echo ""
    exit 1
else 
    echo "Test pod started correctly"
fi


#start the podsniffer script
echo ""
echo "Script ${snifferscript} execution: "
echo "--------------------------------------------------------------------"
${snifferscript} ${podtest} -d 30
echo "--------------------------------------------------------------------"


#clean-up
echo "Cleaning-up..."
${kubectl} delete jobs/${podtestjob} > /dev/null 2>&1
echo "Test terminated!"
echo ""
exit 0