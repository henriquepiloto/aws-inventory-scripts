# aws-inventory-scripts
# 🛠️ AWS Inventory Scripts - RDS & EKS

Scripts automatizados para geração de inventário de clusters **RDS** e **EKS** em múltiplas contas AWS, com salvamento dos relatórios em **Excel** no Amazon S3.

---

## 📌 Funcionalidades

- Assume Role em múltiplas contas AWS.
- Percorre regiões válidas da AWS.
- Coleta:
  - Para **RDS**: `Cluster ID`, `Engine`, `Engine Version`, `Região`, `Conta`.
  - Para **EKS**: `Cluster Name`, `Kubernetes Version`, `Status`, `Created At`, `Região`, `Conta`.
- Salva relatório `.xlsx` localmente e envia para um bucket S3.
- `roles.json` é carregado diretamente do S3 para maior segurança.

---

## 📦 Pré-requisitos

- Python 3.7+
- AWS CLI configurado
- Permissões para:
  - `sts:AssumeRole`
  - `rds:DescribeDBClusters`
  - `eks:ListClusters`, `eks:DescribeCluster`
  - `s3:GetObject`, `s3:PutObject`

Instale os pacotes:

```bash
pip install -r requirements.txt
