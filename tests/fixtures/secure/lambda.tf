resource "aws_lambda_function" "inference" {
  function_name = "prod-inference"
  role          = aws_iam_role.lambda_ai.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id]
    security_group_ids = [aws_security_group.lambda.id]
  }
  environment {
    variables = {
      BEDROCK_MODEL_ID = "anthropic.claude-3-sonnet"
    }
  }
}
