#!/bin/bash

#### Make sure you have Docker engine installed on the host ####
###### TODO - Support parameters ######

export AWS_ACCESS_KEY_ID=xxxxxxxxxx
export AWS_SECRET_ACCESS_KEY=xxxxxxxxx
export AWS_DEFAULT_REGION=ap-south-1
export AWS_DEFAULT_OUTPUT=json
export S3_BUCKET_NAME=my-es-migration-bucket
export DATE=$(date +%d-%b-%H_%M)

old_instance="https://vpc-my-es-ykp2tlrxonk23dblqkseidmllu.ap-southeast-1.es.amazonaws.com"
new_instance="https://vpc-my-es-mg5td7bqwp4zuiddwgx2n474sm.ap-south-1.es.amazonaws.com"
delete=(.kibana)
es_indexes=$(curl -s "${old_instance}/_cat/indices" | awk '{ print $3 }')
es_indexes=${es_indexes//$delete/}
es_indexes=$(echo $es_indexes|tr -d '\n')

echo "index to be copied are - $es_indexes"

for index in $es_indexes; do

# Export ES data to S3 (using s3urls) 
docker run --rm -ti taskrabbit/elasticsearch-dump \
  --s3AccessKeyId "${AWS_ACCESS_KEY_ID}" \
  --s3SecretAccessKey "${AWS_SECRET_ACCESS_KEY}" \
  --input="${old_instance}/${index}" \
  --output "s3://${S3_BUCKET_NAME}/${index}-${DATE}.json"

# Import data from S3 into ES (using s3urls) 
docker run --rm -ti taskrabbit/elasticsearch-dump \
  --s3AccessKeyId "${AWS_ACCESS_KEY_ID}" \
  --s3SecretAccessKey "${AWS_SECRET_ACCESS_KEY}" \
  --input "s3://${S3_BUCKET_NAME}/${index}-${DATE}.json" \
  --output="${new_instance}/${index}"

new_indexes=$(curl -s "${new_instance}/_cat/indices" | awk '{ print $3 }')
echo $new_indexes
curl -s "${new_instance}/_cat/indices"

done
