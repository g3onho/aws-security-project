# 원격 state. bootstrap 이 만든 버킷/잠금테이블을 가리킵니다.
# 로컬에서 처음 전환할 때만: terraform init -migrate-state
#
# 2026-09-30 서울→파리 이전: 리전마다 state 를 따로 둡니다. 리소스 ID 는 리전에 묶여 있어서
# 같은 state 로 리전만 바꾸면 "옛 리전 리소스 삭제 + 없는 VPC 에 신규 생성"이 섞여 깨집니다.
#   서울 정리용(옛 배포):  key = "soar-sec/terraform.tfstate"        + -var region=ap-northeast-2
#   파리 신규 배포:        key = "soar-sec-paris/terraform.tfstate"  (region 기본값 eu-west-3)
# 전환할 때마다 terraform init -reconfigure 가 필요합니다.
# 버킷·잠금테이블은 서울에 그대로 둡니다(state 저장 위치는 배포 리전과 무관).
terraform {
  backend "s3" {
    bucket = "soar-sec-tfstate-455958489281"
    # key  = "soar-sec/terraform.tfstate"
    key            = "soar-sec-paris/terraform.tfstate"
    region         = "ap-northeast-2"
    dynamodb_table = "soar-sec-tflock"
    encrypt        = true
  }
}
