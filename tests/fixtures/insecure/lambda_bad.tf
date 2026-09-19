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
resource "aws_lambda_function" "textract_agent" {
  function_name = "textract-agent"
  role          = aws_iam_role.agent_role.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id]
    security_group_ids = [aws_security_group.lambda.id]
  }
  environment {
    variables = {
      TEXTRACT_ROLE_ARN = "arn:aws:iam::123456789012:role/textract-caller"
    }
  }
}
# "lex" is the one service whose real VPC endpoint name has a hyphen, not a
# dot, before the word (models-v2-lex, runtime-v2-lex) - this fixture
# exercises the bare-word signal and endpoint match specifically, not just
# the dot-prefixed shape every other new service uses.
resource "aws_lambda_function" "lex_agent" {
  function_name = "lex-agent"
  role          = aws_iam_role.agent_role.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id]
    security_group_ids = [aws_security_group.lambda.id]
  }
  environment {
    variables = {
      LEX_BOT_ID = "ABCDEFGH12"
    }
  }
}
