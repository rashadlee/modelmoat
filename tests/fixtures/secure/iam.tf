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
# Deliberately no AI-service permissions anywhere on this role or its
# policy - isolates the word-collision negative control fixture from
# picking up a role-based signal that has nothing to do with what's
# actually being tested (whole-token matching on the Lambda's own
# environment variables).
resource "aws_iam_role" "generic_lambda" {
  name               = "prod-generic-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" } }]
  })
}
resource "aws_iam_role_policy" "generic_lambda_logs" {
  name = "cloudwatch-logs-only"
  role = aws_iam_role.generic_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/*"]
    }]
  })
}
