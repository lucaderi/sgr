#!/bin/bash


pod=""
podsniffer=""
namespace="default"
capture_duration="100"
now=$(date +%s)
podsnifferjob="pod-sniffer-job-${now}"
script="$0"

if [ -x "/snap/bin/microk8s.kubectl" ]; then
    kubectl="/snap/bin/microk8s.kubectl"
else 
    kubectl=$(which kubectl)
fi

function main() {
  pods_list
  parse_arguments "$@"
  start_capture
}


function usage() {
  cat << EOF
Usage: ${script} POD-NAME [-ns NAMESPACE] [-d DURATION]
Options:
  -ns|--namespace    The namespace where the target pod lives (default: default)
  -d|--duration      The capture duration (default: 100s)

EOF
  exit 1
}


function pods_list() {
  echo ""
  echo "PODS LIST:"
  for listNamespace in $($kubectl get namespace -o jsonpath='{.items[*].metadata.name}'); do
      echo "namespace:$listNamespace"
      for listPod in $($kubectl get pod --namespace=$listNamespace -o jsonpath='{.items[*].metadata.name}'); do
        echo "   pod:$listPod"
        for container in $($kubectl get pod $listPod --namespace=$listNamespace -o jsonpath='{.status.containerStatuses[*].containerID}'); do
          echo "      container:$container"
        done
      done
  done
  echo ""
}


function parse_arguments() {
  if [[ $# < 1 ]]; then
    usage
  fi

  pod="$1"
  shift

  while [ $# -gt 0 ]
  do
    case $1 in
      -ns|--namespace)
        namespace=$2
        shift
        ;;
      -d|--duration)
        capture_duration=$2
        shift
        ;;
      *)
        usage
        ;;
    esac
    shift
  done

  if [[ ! ${capture_duration} =~ ^[[:digit:]]+$ ]]; then
    echo "Error: capture duration must be a positive integer"
    echo ""
    exit 1
  fi

  if [[ ${capture_duration} < 0 ]]; then
    echo "Error: capture duration must be a positive integer"
    echo ""
    exit 1
  fi
}


function start_capture() {
  node=$(${kubectl} -n ${namespace} get pod ${pod} -o jsonpath='{.spec.nodeName}' 2>/dev/null)
  if [[ $? -ne 0 ]];then
    echo "Error: Unable to trigger a capture on pod ${pod}"
    echo ""
    exit 1
  fi

  index=$(${kubectl} exec ${pod} --namespace=${namespace} cat /sys/class/net/eth0/iflink 2>/dev/null)
  if [[ $? -ne 0 ]];then
    echo "Error: Unable to trigger a capture on pod ${pod}"
    echo ""
    exit 1
  fi

  cat << EOF > podsniffer.yaml
  apiVersion: batch/v1
  kind: Job
  metadata:
    name: ${podsnifferjob}
  spec:
    template:
      metadata:
        name: pod-sniffer-pod
      spec:
        hostNetwork: true
        containers:
        - name: pod-sniffer
          image: "docker.io/centos/tools"
          command: ["/bin/bash", "-c", "--"]
          args: [ "inter=\$(ip link | grep ^${index}) ; tmp=\${inter#*' '} ; tmp2=\${tmp%:*} ; final=\${tmp2%@*} ; tcpdump -i \${final} -U -s0 -vv -n -w mycap.pcap" ]
        restartPolicy: Never 
EOF

  ${kubectl} apply -f podsniffer.yaml > /dev/null 2>&1
  rm podsniffer.yaml

  podsniffer=$(${kubectl} get pods --selector=job-name=${podsnifferjob} --output=jsonpath='{.items[*].metadata.name}')
  if [[ $? -ne 0 ]];then
    ${kubectl} delete jobs/${podsnifferjob} > /dev/null 2>&1
    echo "Error: job has not started"
    echo ""
    exit 1
  fi

  echo "Start capture on:"
  echo "  Node: ${node}"
  echo "  Namespace: ${namespace}"
  echo "  Pod: ${pod}"
  echo "  Duration: ${capture_duration} seconds"
  echo "Capturing..."

  sleep 3

  status=$(${kubectl} get pod ${podsniffer} --output=jsonpath='{.status.phase}')
  if [[ "${status}" = "Failed" ]];then
    ${kubectl} delete jobs/${podsnifferjob} > /dev/null 2>&1
    echo "Error: job has not started correctly"
    echo ""
    exit 1
  fi

  sleep ${capture_duration}

  capture_file="capture-${pod}-${now}.pcap"
  ${kubectl} cp ${podsniffer}:mycap.pcap ${capture_file} > /dev/null 2>&1
  ${kubectl} delete jobs/${podsnifferjob} > /dev/null 2>&1
  echo "Capture over!"

  if [ -e "./${capture_file}" ];then
    echo "The capture has been downloaded to your hard disk at:"
    echo " ${PWD}/${capture_file}"
  else 
    echo " attention: no package has been captured."
  fi
  

  echo ""
  exit 0
}


trap delete_pod_sniffer INT

function delete_pod_sniffer() {
  if [[ -n "${podsniffer}" ]]; then
    echo ""
    echo "Please wait until pod sniffer is deleted..."
    ${kubectl} delete jobs/${podsnifferjob} > /dev/null 2>&1
    echo "Pod sniffer deleted"
  fi
  exit 0
}


main "$@"