############################################
# GitHub Actions OIDC — 액세스 키 없이 AWS 접근
#
# 액세스 키를 GitHub Secrets 에 넣지 않습니다(학생가이드 5.2).
# GitHub 이 발급한 단기 토큰을 AWS STS 가 검증해 1시간짜리 임시 자격증명을 줍니다.
#
# 사용:
#   terraform apply -var="github_repo=계정명/리포지토리명"
#
# github_repo 를 비워두면(기본값) 아무것도 만들지 않습니다.
############################################

variable "github_repo" {
  description = <<-EOT
    OIDC 를 허용할 GitHub 리포지토리 (owner/repo 형식).
    OIDC 토큰의 sub 클레임과 문자 그대로 비교하므로 대소문자까지 정확해야 합니다.
    비우면 OIDC 관련 자원을 만들지 않습니다.
  EOT
  type        = string
  default     = "juhyeop/aws-security-project"
}

variable "github_plan_branches" {
  description = "plan 만 허용할 참조 패턴. PR 은 pull_request 컨텍스트로 들어옵니다."
  type        = list(string)
  default     = ["pull_request"]
}

variable "github_apply_branch" {
  description = "apply 를 허용할 브랜치."
  type        = string
  default     = "main"
}

locals {
  oidc_enabled = var.github_repo != ""
}

# GitHub 의 OIDC 공급자. 계정에 이미 있으면 이 리소스를 빼고 data 로 참조하세요.
resource "aws_iam_openid_connect_provider" "github" {
  count = local.oidc_enabled ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

############################################
# plan 용 역할 — 읽기 전용 + state 접근
############################################

data "aws_iam_policy_document" "plan_assume" {
  count = local.oidc_enabled ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # PR 과 대상 브랜치 양쪽에서 plan 을 돌릴 수 있게 합니다.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = concat(
        [for b in var.github_plan_branches : "repo:${var.github_repo}:${b}"],
        ["repo:${var.github_repo}:ref:refs/heads/${var.github_apply_branch}"]
      )
    }
  }
}

resource "aws_iam_role" "plan" {
  count = local.oidc_enabled ? 1 : 0

  name                 = "github-actions-terraform-plan"
  description          = "GitHub Actions - terraform plan (read only)"
  assume_role_policy   = data.aws_iam_policy_document.plan_assume[0].json
  max_session_duration = 3600
}

# plan 은 읽기만 하면 됩니다.
resource "aws_iam_role_policy_attachment" "plan_readonly" {
  count = local.oidc_enabled ? 1 : 0

  role       = aws_iam_role.plan[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# state 버킷 읽기 + 잠금 테이블. plan 도 잠금을 잡습니다.
data "aws_iam_policy_document" "state_access" {
  count = local.oidc_enabled ? 1 : 0

  statement {
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.state.arn}/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.lock.arn]
  }
}

resource "aws_iam_role_policy" "plan_state" {
  count = local.oidc_enabled ? 1 : 0

  name   = "terraform-state-access"
  role   = aws_iam_role.plan[0].id
  policy = data.aws_iam_policy_document.state_access[0].json
}

############################################
# apply 용 역할 — main 브랜치에서만
############################################

data "aws_iam_policy_document" "apply_assume" {
  count = local.oidc_enabled ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # PR 에서는 이 역할을 빌릴 수 없습니다. main 브랜치 전용.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/${var.github_apply_branch}"]
    }
  }
}

resource "aws_iam_role" "apply" {
  count = local.oidc_enabled ? 1 : 0

  name                 = "github-actions-terraform-apply"
  description          = "GitHub Actions - terraform apply (main branch only)"
  assume_role_policy   = data.aws_iam_policy_document.apply_assume[0].json
  max_session_duration = 3600
}

# ponytail: 학습용이라 PowerUserAccess + IAM 최소권한으로 시작합니다.
# 실제 운영이라면 plan 실패할 때마다 필요한 액션만 추가하는 방식이 맞습니다.
resource "aws_iam_role_policy_attachment" "apply_power" {
  count = local.oidc_enabled ? 1 : 0

  role       = aws_iam_role.apply[0].name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# PowerUserAccess 에는 IAM 쓰기가 없습니다. 이 프로젝트는 역할을 만들기 때문에 따로 붙입니다.
data "aws_iam_policy_document" "apply_iam" {
  count = local.oidc_enabled ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:UpdateRole",
      "iam:TagRole", "iam:UntagRole", "iam:ListRoleTags",
      "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:ListAttachedRolePolicies",
      "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy", "iam:ListRolePolicies",
      "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile",
      "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile",
      "iam:CreateServiceLinkedRole", "iam:PassRole",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "apply_iam" {
  count = local.oidc_enabled ? 1 : 0

  name   = "terraform-iam-write"
  role   = aws_iam_role.apply[0].id
  policy = data.aws_iam_policy_document.apply_iam[0].json
}

resource "aws_iam_role_policy" "apply_state" {
  count = local.oidc_enabled ? 1 : 0

  name   = "terraform-state-access"
  role   = aws_iam_role.apply[0].id
  policy = data.aws_iam_policy_document.state_access[0].json
}

############################################
# 출력 — 워크플로에 넣을 값
############################################

output "github_plan_role_arn" {
  description = "워크플로의 TF_PLAN_ROLE 에 넣을 값"
  value       = local.oidc_enabled ? aws_iam_role.plan[0].arn : "(github_repo 미지정)"
}

output "github_apply_role_arn" {
  description = "워크플로의 TF_APPLY_ROLE 에 넣을 값"
  value       = local.oidc_enabled ? aws_iam_role.apply[0].arn : "(github_repo 미지정)"
}
