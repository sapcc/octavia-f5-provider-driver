#!/bin/sh

TERMINATE=0

_term() {
  echo "Caught SIGTERM signal!"
  TERMINATE=1
  killall terraform
}

trap _term SIGTERM

terraform init


# Minimal prometheus exporter
echo "# terraform octavia performance metrics" > prom.html
sh -c 'while true; do { echo -ne "HTTP/1.0 200 OK\r\n\r\n"; cat prom.html; } | nc -l -p 8080; done' &


while true
do
  START_TIME=$(date +%s)
  echo START: $START_TIME
  time terraform apply -auto-approve -var-file="secrets.tfvars" -parallelism=15
  apply_duration=$(($(date +%s) - $START_TIME))
  echo DURATION: $apply_duration
  echo "$(($apply_duration / 60)) minutes and $(($apply_duration % 60)) seconds elapsed."
  if [ $TERMINATE = 1 ]; then exit; fi
  sleep 10
  
  START_TIME=$(date +%s)
  echo START: $START_TIME
  time terraform destroy -auto-approve -var-file="secrets.tfvars" -parallelism=15
  destroy_duration=$(($(date +%s) - $START_TIME))
  echo DURATION: $destroy_duration
  echo "$(($destroy_duration / 60)) minutes and $(($destroy_duration % 60)) seconds elapsed."
  if [ $TERMINATE = 1 ]; then exit; fi

  echo -e "# terraform octavia performance metrics\nterraform_octavia_apply_duration $apply_duration\nterraform_octavia_destroy_duration $destroy_duration\n" > prom.html
  sleep 60
done
