resource "aws_iam_role" "agent_role" {
  name = "agent-role"
}
resource "aws_iam_role_policy" "wide_open" {
  name = "wide-open"
  role = aws_iam_role.agent_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["bedrock:*", "sagemaker:*"], Resource = "*" }]
  })
}
resource "aws_iam_role_policy_attachment" "full_access" {
  role       = aws_iam_role.agent_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
}
data "aws_iam_policy_document" "sagemaker_admin" {
  statement {
    effect    = "Allow"
    actions   = ["sagemaker:*"]
    resources = ["*"]
  }
}
resource "aws_iam_policy" "sagemaker_admin" {
  name   = "sagemaker-admin"
  policy = data.aws_iam_policy_document.sagemaker_admin.json
}
resource "aws_iam_role_policy_attachment" "sagemaker_admin" {
  role       = aws_iam_role.agent_role.name
  policy_arn = aws_iam_policy.sagemaker_admin.arn
}
