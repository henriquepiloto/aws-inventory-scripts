import boto3
import json
import datetime
import pandas as pd
from botocore.exceptions import ClientError

BUCKET_NAME = "script-piloto"
ROLES_KEY = "tsj.json"
REGIOES_VALIDAS = ["us-east-1"]
output_prefix = "relatorios/"
output_local_prefix = "/tmp/"

def get_roles_from_s3():
    s3 = boto3.client("s3")
    obj = s3.get_object(Bucket=BUCKET_NAME, Key=ROLES_KEY)
    return json.loads(obj['Body'].read())

def assume_role(account_id, role_name):
    sts = boto3.client("sts")
    response = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
        RoleSessionName="AuditSession"
    )
    return response['Credentials']

def make_creds_dict(creds):
    return {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"]
    }

def check_iam(creds, cliente, account_id):
    iam = boto3.client("iam", **creds)
    findings = []

    # MFA Check
    users = iam.list_users()["Users"]
    for user in users:
        uname = user["UserName"]
        pwd_used = user.get("PasswordLastUsed")
        has_console_access = pwd_used is not None

        mfa_devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
        if has_console_access and not mfa_devices:
            findings.append({
                "Conta": cliente,
                "ID da Conta": account_id,
                "Serviço": "IAM",
                "Descrição": f"Usuário IAM sem MFA: {uname}",
                "Motivo": "Usuários IAM com acesso à console devem ter MFA habilitado para evitar acesso não autorizado.",
                "Severidade": "Alta",
                "Recomendacao de solucao": "Ative o MFA para o usuário no IAM."
            })

        # Access key check
        keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
        for key in keys:
            age = (datetime.datetime.now(datetime.timezone.utc) - key["CreateDate"]).days
            if age > 90:
                findings.append({
                    "Conta": cliente,
                    "ID da Conta": account_id,
                    "Serviço": "IAM",
                    "Descrição": f"Chave de acesso antiga (>90 dias): {uname}",
                    "Motivo": "Chaves de acesso antigas aumentam o risco de comprometimento.",
                    "Severidade": "Média",
                    "Recomendacao de solucao": "Rode política de rotação e crie novas chaves."
                })

    # Roles com permissões amplas
    roles = iam.list_roles()["Roles"]
    for role in roles:
        name = role["RoleName"]
        try:
            policies = iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
            for p in policies:
                policy = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]
                version = iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=policy["DefaultVersionId"])
                stmts = version["PolicyVersion"]["Document"].get("Statement", [])
                if not isinstance(stmts, list):
                    stmts = [stmts]
                for stmt in stmts:
                    if "*" in str(stmt.get("Action")) or "*" in str(stmt.get("Resource")):
                        findings.append({
                            "Conta": cliente,
                            "ID da Conta": account_id,
                            "Serviço": "IAM",
                            "Descrição": f"Role com permissões amplas (*): {name}",
                            "Motivo": "Permissões com curingas (*) permitem acesso irrestrito e representam alto risco.",
                            "Severidade": "Alta",
                            "Recomendacao de solucao": "Restringir as permissões da role com políticas mais específicas."
                        })
        except Exception:
            continue

    return findings

def main():
    relatorio = []
    roles = get_roles_from_s3()
    for entry in roles:
        account_id = entry["account_id"]
        role_name = entry["role_name"]
        cliente = entry.get("cliente", "Desconhecido")

        creds_raw = assume_role(account_id, role_name)
        creds = make_creds_dict(creds_raw)

        print(f"[Verificando conta {cliente} ({account_id})]")
        relatorio.extend(check_iam(creds, cliente, account_id))

    # Gera relatório Excel
    if relatorio:
        df = pd.DataFrame(relatorio)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
        filename = f"relatorio_seg_{timestamp}.xlsx"
        df.to_excel(filename, index=False)
        print(f"[✓] Relatório salvo: {filename}")

        # Upload para o S3
        s3_client = boto3.client("s3")
        try:
            s3_key = output_prefix + filename
            s3_client.upload_file(filename, BUCKET_NAME, s3_key)
            print(f"[✓] Upload para o S3 realizado: s3://{BUCKET_NAME}/{s3_key}")
        except Exception as e:
            print(f"[x] Erro ao enviar para o S3: {e}")
    else:
        print("[INFO] Nenhum item de segurança encontrado.")

if __name__ == "__main__":
    main()
