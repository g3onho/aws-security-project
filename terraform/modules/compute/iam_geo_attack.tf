# 지리별 웹보안검사 [시작] — 대시보드 롤이 각 리전 공격자에 ATK-WebAttack 실행
resource "aws_iam_role_policy" "dashboard_geo_attack" {
  name = "${var.name_prefix}-dashboard-geo-attack"
  role = aws_iam_role.dashboard.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RunGeoAttack"
        Effect = "Allow"
        Action = ["ssm:SendCommand"]
        Resource = [
          "arn:${var.partition}:ssm:*:${var.account_id}:document/${var.name_prefix}-ATK-WebAttack",
          "arn:${var.partition}:ec2:*:${var.account_id}:instance/*"
        ]
      },
      {
        Sid      = "ReadGeoAttackStatus"
        Effect   = "Allow"
        Action   = ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations", "ssm:ListCommands"]
        Resource = "*"
      }
    ]
  })
}
