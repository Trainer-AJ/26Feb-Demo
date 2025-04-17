import boto3

ec2 = boto.resource("ec2")

client = ec2(access_key = "hgfd76876r7r", secret_key = "nooPho4ae5ooyai2873498")

client.describe_instances()
