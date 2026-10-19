#!/bin/sh

set -eu

bucket="$LOCAL_FIRST_CYCLE_BUCKET"
queue="$LOCAL_FIRST_CYCLE_QUEUE"
dlq="$LOCAL_FIRST_CYCLE_DLQ"
region="$AWS_DEFAULT_REGION"

awslocal sqs create-queue --queue-name "$dlq" >/dev/null
dlq_url="$(awslocal sqs get-queue-url --queue-name "$dlq" --query QueueUrl --output text)"
dlq_arn="$(awslocal sqs get-queue-attributes --queue-url "$dlq_url" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)"

awslocal sqs create-queue --queue-name "$queue" >/dev/null
queue_url="$(awslocal sqs get-queue-url --queue-name "$queue" --query QueueUrl --output text)"
queue_arn="$(awslocal sqs get-queue-attributes --queue-url "$queue_url" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)"

awslocal sqs set-queue-attributes \
  --queue-url "$queue_url" \
  --attributes "{\"RedrivePolicy\":\"{\\\"deadLetterTargetArn\\\":\\\"$dlq_arn\\\",\\\"maxReceiveCount\\\":\\\"3\\\"}\"}" >/dev/null

awslocal s3api create-bucket \
  --bucket "$bucket" \
  --create-bucket-configuration "LocationConstraint=$region" >/dev/null 2>&1 || true

notification_file="$(mktemp)"
cat > "$notification_file" <<EOF
{
  "QueueConfigurations": [
    {
      "Id": "first-cycle-sysmon-created",
      "QueueArn": "$queue_arn",
      "Events": ["s3:ObjectCreated:*"],
      "Filter": {
        "Key": {
          "FilterRules": [
            {"Name": "prefix", "Value": "incoming/first-cycle/sysmon/"},
            {"Name": "suffix", "Value": "sysmon.jsonl"}
          ]
        }
      }
    }
  ]
}
EOF

awslocal s3api put-bucket-notification-configuration \
  --bucket "$bucket" \
  --notification-configuration "file://$notification_file"
rm -f "$notification_file"

printf 'Initialized LocalStack First Cycle resources: s3://%s and %s\n' "$bucket" "$queue_url"
