############################################
# ECR — Inspector2 컨테이너 이미지 스캔 대상 (SEC-04)
# Inspector2 의 이미지 스캔은 ECR 에 push 된 이미지를 대상으로 합니다.
############################################

resource "aws_ecr_repository" "app" {
  name                 = "${var.name_prefix}/app"
  image_tag_mutability = "IMMUTABLE" # latest 재사용 방지 (체크리스트 #21)
  force_delete         = true        # 실습 종료 시 destroy 를 막지 않도록

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = merge(var.tags, { Scenario = "SEC-04" })
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}
