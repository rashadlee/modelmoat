resource "aws_iam_role" "lambda_ai" {
  name               = "prod-lambda-ai-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" } }]
  })
}
resource "aws_iam_role_policy" "lambda_ai_scoped" {
  name = "invoke-claude-only"
  role = aws_iam_role.lambda_ai.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      Resource = ["arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet"]
    }]
  })
}
