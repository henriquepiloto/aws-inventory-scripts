import boto3
import json
import datetime
import pandas as pd
from botocore.exceptions import ClientError

# Configurações
bucket_name = "script-piloto"
roles_key = "roles.json"
output_prefix = "EKS/"  # <- salva na pasta EKS

# Sessão base
session = boto3.session.Session()
sts_client = session.client("sts")
s3_client = session.client("s3")

# Carrega roles.json do S3
print(f"[INFO] Carregando {roles_key} do bucket {bucket_name}...")
try:
    roles_obj = s3_client.get_object(Bucket=bucket_name, Key=roles_key)
    roles_data = json.loads(roles_obj['Body'].read())
except Exception as e:
    print(f"[FALHA] Não foi possível ler o roles.json do S3: {e}")
    exit(1)

# Regiões válidas
REGIOES_VALIDAS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "sa-east-1", "ca-central-1", "eu-west-1", "eu-west-2",
    "eu-west-3", "eu-central-1", "ap-south-1", "ap-northeast-1",
    "ap-northeast-2", "ap-southeast-1", "ap-northeast-3"
]

resultado_eks = []

for entry in roles_data:
    cliente = entry["cliente"]
    account_id = entry["account_id"]
    role_name = entry["role_name"]

    print(f"[INFO] Acessando {cliente} ({account_id})...")

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="EksCheckSession"
        )

        creds = assumed_role["Credentials"]

        for region in REGIOES_VALIDAS:
            try:
                eks_client = boto3.client(
                    "eks",
                    region_name=region,
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                )

                clusters = eks_client.list_clusters()["clusters"]
                for cluster_name in clusters:
                    cluster = eks_client.describe_cluster(name=cluster_name)["cluster"]

                    resultado_eks.append({
                        "Cliente": cliente,
                        "Account ID": account_id,
                        "Região": region,
                        "Cluster Name": cluster["name"],
                        "Kubernetes Version": cluster["version"],
                        "Status": cluster["status"],
                        "Created At": cluster["createdAt"].strftime("%Y-%m-%d %H:%M:%S")
                    })

            except ClientError as e:
                print(f"[ERRO] Falha na região {region} da conta {account_id}: {e}")
                continue

    except ClientError as e:
        print(f"[ERRO] Falha ao assumir role {role_arn}: {e}")
        continue

# Geração do Excel
if resultado_eks:
    df = pd.DataFrame(resultado_eks)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = f"eks_clusters_{timestamp}.xlsx"
    df.to_excel(filename, index=False)
    print(f"[SUCESSO] Relatório salvo localmente como: {filename}")

    # Envio ao S3
    s3_key = f"{output_prefix}{filename}"
    try:
        s3_client.upload_file(filename, bucket_name, s3_key)
        print(f"[SUCESSO] Arquivo enviado para: s3://{bucket_name}/{s3_key}")
    except Exception as e:
        print(f"[ERRO] Falha ao enviar para S3: {e}")
else:
    print("[INFO] Nenhum cluster EKS encontrado ou erro ao assumir roles.")
