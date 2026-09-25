# 원격 state. bootstrap 이 만든 버킷/잠금테이블을 가리킵니다.
# 로컬에서 처음 전환할 때만: terraform init -migrate-state
terraform {
  backend "s3" {
    bucket         = "soar-sec-tfstate-455958489281"
    key            = "soar-sec/terraform.tfstate"
    region         = "ap-northeast-2"
    dynamodb_table = "soar-sec-tflock"
    encrypt        = true
  }
}
