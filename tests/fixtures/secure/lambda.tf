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
resource "aws_lambda_function" "textract_caller" {
  function_name = "prod-textract-caller"
  role          = aws_iam_role.lambda_ai.arn
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
# "polly" and "lex" are short enough to collide with ordinary words as a
# substring - "monopoly" contains "polly", "complex" contains "lex". Whole
# -token matching must not fire on either, the same negative-control
# discipline "email" not matching "ai" and "html" not matching "ml"
# already gets elsewhere in this project.
resource "aws_lambda_function" "unrelated_word_collision" {
  function_name = "unrelated-word-collision"
  role          = aws_iam_role.generic_lambda.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  environment {
    variables = {
      GAME_CONFIG   = "monopoly-board-v2"
      BUILD_SETTING = "complex-optimization-flags"
    }
  }
}
