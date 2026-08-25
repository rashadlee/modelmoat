resource "aws_lambda_function" "vpc_agent" {
  function_name = "vpc-agent"
  role          = aws_iam_role.agent_role.arn
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
resource "aws_lambda_function" "public_agent" {
  function_name = "public-agent"
  role          = aws_iam_role.agent_role.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  environment {
    variables = {
      SAGEMAKER_ENDPOINT_NAME = "prod-llm"
    }
  }
}
