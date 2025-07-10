
import boto3
import json
from botocore.exceptions import ClientError

BUCKET_NAME = "script-piloto"
ROLES_KEY = "roles.json"
REGIOES_VALIDAS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "sa-east-1", "ca-central-1", "eu-west-1", "eu-west-2",
    "eu-west-3", "eu-central-1"
]

def get_roles_from_s3():
    s3 = boto3.client("s3")
    try:
        obj = s3.get_object(Bucket=BUCKET_NAME, Key=ROLES_KEY)
        return json.loads(obj['Body'].read())
    except Exception as e:
        print(f"[ERRO] Falha ao ler roles.json: {e}")
        exit(1)

def assume_role(account_id, role_name):
    sts = boto3.client("sts")
    try:
        response = sts.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName="TaggingSession"
        )
        return response['Credentials']
    except Exception as e:
        print(f"[ERRO] Não foi possível assumir a role da conta {account_id}: {e}")
        return None

def tag_ec2(region, creds):
    ec2 = boto3.client("ec2", region_name=region, **creds)
    try:
        instances = ec2.describe_instances()["Reservations"]
        for r in instances:
            for i in r["Instances"]:
                iid = i["InstanceId"]
                tags = i.get("Tags", [])
                if not any(tag["Key"] == "Name" for tag in tags):
                    ec2.create_tags(Resources=[iid], Tags=[{"Key": "Name", "Value": iid}])
                    print(f"[✓] EC2 {iid} taggeada")
    except Exception as e:
        print(f"[x] EC2: {e}")

def tag_eks(region, creds):
    eks = boto3.client("eks", region_name=region, **creds)
    try:
        for cluster in eks.list_clusters()["clusters"]:
            desc = eks.describe_cluster(name=cluster)["cluster"]
            tags = desc.get("tags", {})
            if "Name" not in tags:
                eks.tag_resource(resourceArn=desc["arn"], tags={"Name": cluster})
                print(f"[✓] EKS {cluster} taggeado")
    except Exception as e:
        print(f"[x] EKS: {e}")

def tag_s3(region, creds):
    s3 = boto3.client("s3", region_name=region, **creds)
    try:
        buckets = s3.list_buckets()["Buckets"]
        for b in buckets:
            name = b["Name"]
            try:
                tags = s3.get_bucket_tagging(Bucket=name)["TagSet"]
            except:
                tags = []
            if not any(tag["Key"] == "Name" for tag in tags):
                tags.append({"Key": "Name", "Value": name})
                s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": tags})
                print(f"[✓] S3 {name} taggeado")
    except Exception as e:
        print(f"[x] S3: {e}")

def tag_rds(region, creds):
    rds = boto3.client("rds", region_name=region, **creds)
    try:
        clusters = rds.describe_db_clusters()["DBClusters"]
        for c in clusters:
            arn = c["DBClusterArn"]
            name = c["DBClusterIdentifier"]
            tags = rds.list_tags_for_resource(ResourceName=arn)["TagList"]
            if not any(t["Key"] == "Name" for t in tags):
                rds.add_tags_to_resource(ResourceName=arn, Tags=[{"Key": "Name", "Value": name}])
                print(f"[✓] RDS cluster {name} taggeado")
        instances = rds.describe_db_instances()["DBInstances"]
        for i in instances:
            arn = i["DBInstanceArn"]
            name = i["DBInstanceIdentifier"]
            tags = rds.list_tags_for_resource(ResourceName=arn)["TagList"]
            if not any(t["Key"] == "Name" for t in tags):
                rds.add_tags_to_resource(ResourceName=arn, Tags=[{"Key": "Name", "Value": name}])
                print(f"[✓] RDS instance {name} taggeada")
    except Exception as e:
        print(f"[x] RDS: {e}")

def tag_ecc(region, creds):
    ecc = boto3.client("elasticache", region_name=region, **creds)
    try:
        clusters = ecc.describe_cache_clusters(ShowCacheNodeInfo=False)["CacheClusters"]
        for c in clusters:
            arn = c["ARN"]
            name = c["CacheClusterId"]
            tags = ecc.list_tags_for_resource(ResourceName=arn)["TagList"]
            if not any(t["Key"] == "Name" for t in tags):
                ecc.add_tags_to_resource(ResourceName=arn, Tags=[{"Key": "Name", "Value": name}])
                print(f"[✓] ECC {name} taggeado")
    except Exception as e:
        print(f"[x] ECC: {e}")

def tag_lambda(region, creds):
    lam = boto3.client("lambda", region_name=region, **creds)
    try:
        for func in lam.list_functions()["Functions"]:
            arn = func["FunctionArn"]
            name = func["FunctionName"]
            tags = lam.list_tags(Resource=arn).get("Tags", {})
            if "Name" not in tags:
                lam.tag_resource(Resource=arn, Tags={"Name": name})
                print(f"[✓] Lambda {name} taggeada")
    except Exception as e:
        print(f"[x] Lambda: {e}")

def tag_elbv2(region, creds):
    elb = boto3.client("elbv2", region_name=region, **creds)
    try:
        for lb in elb.describe_load_balancers()["LoadBalancers"]:
            arn = lb["LoadBalancerArn"]
            name = lb["LoadBalancerName"]
            tags = elb.describe_tags(ResourceArns=[arn])["TagDescriptions"][0]["Tags"]
            if not any(t["Key"] == "Name" for t in tags):
                elb.add_tags(ResourceArns=[arn], Tags=[{"Key": "Name", "Value": name}])
                print(f"[✓] ELB {name} taggeado")
    except Exception as e:
        print(f"[x] ELB: {e}")

def tag_vpc(region, creds):
    ec2 = boto3.client("ec2", region_name=region, **creds)
    try:
        for vpc in ec2.describe_vpcs()["Vpcs"]:
            vid = vpc["VpcId"]
            tags = vpc.get("Tags", [])
            if not any(tag["Key"] == "Name" for tag in tags):
                ec2.create_tags(Resources=[vid], Tags=[{"Key": "Name", "Value": vid}])
                print(f"[✓] VPC {vid} taggeada")
    except Exception as e:
        print(f"[x] VPC: {e}")

def tag_nat(region, creds):
    ec2 = boto3.client("ec2", region_name=region, **creds)
    try:
        for nat in ec2.describe_nat_gateways()["NatGateways"]:
            nid = nat["NatGatewayId"]
            tags = nat.get("Tags", [])
            if not any(tag["Key"] == "Name" for tag in tags):
                ec2.create_tags(Resources=[nid], Tags=[{"Key": "Name", "Value": nid}])
                print(f"[✓] NAT {nid} taggeada")
    except Exception as e:
        print(f"[x] NAT: {e}")

def tag_ecs(region, creds):
    ecs = boto3.client("ecs", region_name=region, **creds)
    try:
        clusters = ecs.list_clusters()["clusterArns"]
        for cluster_arn in clusters:
            cluster_name = cluster_arn.split("/")[-1]
            tags = ecs.list_tags_for_resource(resourceArn=cluster_arn).get("tags", [])
            if not any(t["key"] == "Name" for t in tags):
                ecs.tag_resource(resourceArn=cluster_arn, tags=[{"key": "Name", "value": cluster_name}])
                print(f"[✓] ECS Cluster {cluster_name} taggeado")

            services = ecs.list_services(cluster=cluster_arn)["serviceArns"]
            for service_arn in services:
                service_name = service_arn.split("/")[-1]
                tags = ecs.list_tags_for_resource(resourceArn=service_arn).get("tags", [])
                if not any(t["key"] == "Name" for t in tags):
                    ecs.tag_resource(resourceArn=service_arn, tags=[{"key": "Name", "value": service_name}])
                    print(f"[✓] ECS Service {service_name} taggeado")

                tasks = ecs.list_tasks(cluster=cluster_arn, serviceName=service_name)["taskArns"]
                for task_arn in tasks:
                    task_id = task_arn.split("/")[-1]
                    tags = ecs.list_tags_for_resource(resourceArn=task_arn).get("tags", [])
                    if not any(t["key"] == "Name" for t in tags):
                        ecs.tag_resource(resourceArn=task_arn, tags=[{"key": "Name", "value": task_id}])
                        print(f"[✓] ECS Task {task_id} taggeada")
    except Exception as e:
        print(f"[x] ECS: {e}")

def make_creds_dict(creds):
    return {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"]
    }

def main():
    roles = get_roles_from_s3()
    for entry in roles:
        account_id = entry["account_id"]
        role_name = entry["role_name"]
        cliente = entry.get("cliente", "desconhecido")

        creds_raw = assume_role(account_id, role_name)
        if not creds_raw:
            continue
        creds = make_creds_dict(creds_raw)

        for region in REGIOES_VALIDAS:
            print(f"\n[ {cliente} - {account_id} | {region} ]")
            tag_ec2(region, creds)
            tag_eks(region, creds)
            tag_s3(region, creds)
            tag_rds(region, creds)
            tag_ecc(region, creds)
            tag_lambda(region, creds)
            tag_elbv2(region, creds)
            tag_vpc(region, creds)
            tag_nat(region, creds)
            tag_ecs(region, creds)

if __name__ == "__main__":
    main()
