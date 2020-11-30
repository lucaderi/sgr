.PHONY: cAdvisor_up cAdvisor_down all all_tests cpu_test ram_test disco_test cleanup
	
all:
	docker pull ubuntu
	docker build -t test_cpu --file ./Dockerfiles/Dockerfile_cpu .
	docker build -t test_ram --file ./Dockerfiles/Dockerfile_ram .
	docker build -t test_disco --file ./Dockerfiles/Dockerfile_disco .

up_cAdvisor:
	sudo docker run \
  --volume=/:/rootfs:ro \
  --volume=/var/run:/var/run:ro \
  --volume=/sys:/sys:ro \
  --volume=/var/lib/docker/:/var/lib/docker:ro \
  --volume=/dev/disk/:/dev/disk:ro \
  --publish=8080:8080 \
  --detach=true \
  --name=cadvisor \
  --privileged \
  --device=/dev/kmsg \
  gcr.io/google-containers/cadvisor

all_tests:
	docker run test_cpu &
	docker run test_ram &
	docker run test_disco &

cpu_test:
	docker run test_cpu

ram_test:
	docker run test_ram

disco_test:
	docker run test_disco

down_cAdvisor:
	sudo docker container kill cadvisor

cleanup:
	docker image rm -f test_cpu
	docker image rm -f test_ram
	docker image rm -f test_disco
	docker image rm -f ubuntu
