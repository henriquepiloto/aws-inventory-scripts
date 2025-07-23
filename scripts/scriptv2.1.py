import boto3
import json
import datetime
import pandas as pd
from botocore.exceptions import ClientError
from openpyxl import load_workbook
from openpyxl.styles import PatternFill

BUCKET_NAME = "script-piloto"
ROLES_KEY = "tsj.json"
output_prefix = "relatorios/"
output_local_prefix = "/tmp/"

# ------------------------------------
# Funções utilitárias
# ------------------------------------
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

# ------------------------------------
# Lambda Checks
# ------------------------------------
def check_lambda(creds, cliente, account_id):
    findings = []
    try:
        lambda_client = boto3.client("lambda", **creds)
        functions = lambda_client.list_functions()["Functions"]

        for func in functions:
            func_name = func["FunctionName"]
            env_vars = func.get("Environment", {}).get("Variables", {})
            if env_vars:
                findings.append({
                    "Conta": cliente, "ID da Conta": account_id,
                    "Serviço": "Lambda", "Descrição": f"Função {func_name} com variáveis de ambiente",
                    "Motivo": "Verificar se há dados sensíveis não criptografados.",
                    "Severidade": "Média", "Recomendacao de solucao": "Usar KMS para criptografar variáveis sensíveis."
                })
    except Exception:
        return findings
    return findings

# ------------------------------------
# ECS Checks
# ------------------------------------
def check_ecs(creds, cliente, account_id):
    findings = []
    try:
        ecs = boto3.client("ecs", **creds)
        clusters = ecs.list_clusters()["clusterArns"]
        for cluster in clusters:
            services = ecs.list_services(cluster=cluster)["serviceArns"]
            for svc in services:
                svc_desc = ecs.describe_services(cluster=cluster, services=[svc])["services"][0]
                if "taskDefinition" in svc_desc:
                    task_def = ecs.describe_task_definition(taskDefinition=svc_desc["taskDefinition"])["taskDefinition"]
                    if "executionRoleArn" in task_def and ":role/" in task_def["executionRoleArn"]:
                        findings.append({
                            "Conta": cliente, "ID da Conta": account_id,
                            "Serviço": "ECS", "Descrição": f"Serviço {svc} com Role ampla",
                            "Motivo": "Roles com políticas amplas podem causar riscos de segurança.",
                            "Severidade": "Alta", "Recomendacao de solucao": "Restringir permissões IAM da Role."
                        })
    except Exception:
        return findings
    return findings

# ------------------------------------
# EKS Checks
# ------------------------------------
def check_eks(creds, cliente, account_id):
    findings = []
    try:
        eks = boto3.client("eks", **creds)
        clusters = eks.list_clusters()["clusters"]
        for cluster in clusters:
            desc = eks.describe_cluster(name=cluster)["cluster"]
            if desc["resourcesVpcConfig"].get("endpointPublicAccess", False):
                findings.append({
                    "Conta": cliente, "ID da Conta": account_id,
                    "Serviço": "EKS", "Descrição": f"Cluster {cluster} com endpoint público",
                    "Motivo": "Clusters EKS públicos podem ser alvo de ataques.",
                    "Severidade": "Alta", "Recomendacao de solucao": "Desativar endpoint público ou restringir IPs."
                })
    except Exception:
        return findings
    return findings

# ------------------------------------
# Secrets Manager Checks
# ------------------------------------
def check_secrets_manager(creds, cliente, account_id):
    findings = []
    try:
        sm = boto3.client("secretsmanager", **creds)
        secrets = sm.list_secrets()["SecretList"]
        for secret in secrets:
            if not secret.get("RotationEnabled", False):
                findings.append({
                    "Conta": cliente, "ID da Conta": account_id,
                    "Serviço": "Secrets Manager", "Descrição": f"Secret {secret['Name']} sem rotação",
                    "Motivo": "Segredos sem rotação podem ser comprometidos.",
                    "Severidade": "Média", "Recomendacao de solucao": "Ativar rotação automática de segredos."
                })
    except Exception:
        return findings
    return findings

# ------------------------------------
# Elasticache Checks
# ------------------------------------
def check_elasticache(creds, cliente, account_id):
    findings = []
    try:
        ec = boto3.client("elasticache", **creds)
        clusters = ec.describe_cache_clusters(ShowCacheNodeInfo=True)["CacheClusters"]
        for cl in clusters:
            if cl.get("Engine") in ["redis", "memcached"]:
                if cl.get("TransitEncryptionEnabled") is False or cl.get("AtRestEncryptionEnabled") is False:
                    findings.append({
                        "Conta": cliente, "ID da Conta": account_id,
                        "Serviço": "Elasticache", "Descrição": f"Cluster {cl['CacheClusterId']} sem criptografia completa",
                        "Motivo": "Dados podem ser interceptados em trânsito ou em repouso.",
                        "Severidade": "Média", "Recomendacao de solucao": "Ativar criptografia em trânsito e em repouso."
                    })
                if cl.get("CacheClusterStatus") == "available" and cl.get("CacheSubnetGroupName") == "default":
                    findings.append({
                        "Conta": cliente, "ID da Conta": account_id,
                        "Serviço": "Elasticache", "Descrição": f"Cluster {cl['CacheClusterId']} em subnet padrão",
                        "Motivo": "Pode estar exposto a redes públicas.",
                        "Severidade": "Alta", "Recomendacao de solucao": "Usar subnet privada para Elasticache."
                    })
    except Exception:
        return findings
    return findings

# ------------------------------------
# Pontuação
# ------------------------------------
def calcular_pontuacao(relatorio):
    score = 100
    pesos = {"Alta": 5, "Média": 3, "Baixa": 1}
    for item in relatorio:
        score -= pesos.get(item.get("Severidade"), 0)
    return max(score, 0)

# ------------------------------------
# Excel
# ------------------------------------
def format_excel_with_resumo(file_path, relatorio, score):
    df = pd.DataFrame(relatorio)
    with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name="Achados", index=False)
        resumo_df = pd.DataFrame({
            "Severidade": ["Alta", "Média", "Baixa"],
            "Quantidade": [
                df[df["Severidade"] == "Alta"].shape[0],
                df[df["Severidade"] == "Média"].shape[0],
                df[df["Severidade"] == "Baixa"].shape[0],
            ]
        })
        resumo_df.loc[len(resumo_df)] = ["Pontuação Final", score]
        resumo_df.to_excel(writer, sheet_name="Resumo", index=False)

    wb = load_workbook(file_path)
    ws = wb["Achados"]
    severity_fill = {
        "Alta": PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid"),
        "Média": PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid"),
        "Baixa": PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
    }
    for row in ws.iter_rows(min_row=2, max_col=ws.max_column):
        severity = row[5].value
        if severity in severity_fill:
            for cell in row:
                cell.fill = severity_fill[severity]
    wb.save(file_path)

# ------------------------------------
# MAIN
# ------------------------------------
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

        # Serviços já existentes
        relatorio.extend(check_iam(creds, cliente, account_id))
        relatorio.extend(check_s3(creds, cliente, account_id))
        relatorio.extend(check_security_groups(creds, cliente, account_id))
        relatorio.extend(check_rds(creds, cliente, account_id))
        relatorio.extend(check_ebs(creds, cliente, account_id))
        relatorio.extend(check_kms(creds, cliente, account_id))
        relatorio.extend(check_waf(creds, cliente, account_id))
        relatorio.extend(check_config(creds, cliente, account_id))
        relatorio.extend(check_backup(creds, cliente, account_id))
        relatorio.extend(check_efs(creds, cliente, account_id))
        relatorio.extend(check_cloudfront(creds, cliente, account_id))

        # Novos serviços da versão 5.0
        relatorio.extend(check_lambda(creds, cliente, account_id))
        relatorio.extend(check_ecs(creds, cliente, account_id))
        relatorio.extend(check_eks(creds, cliente, account_id))
        relatorio.extend(check_secrets_manager(creds, cliente, account_id))
        relatorio.extend(check_elasticache(creds, cliente, account_id))

    if relatorio:
        score = calcular_pontuacao(relatorio)
        print(f"[✓] Pontuação de segurança: {score}/100")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
        filename = f"relatorio_seg_{timestamp}.xlsx"
        format_excel_with_resumo(filename, relatorio, score)
        print(f"[✓] Relatório salvo: {filename}")

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
