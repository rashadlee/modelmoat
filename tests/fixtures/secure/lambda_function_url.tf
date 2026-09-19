resource "aws_lambda_function" "iam_authed_agent" {
  function_name = "iam-authed-agent"
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
resource "aws_lambda_function_url" "iam_authed_agent" {
  function_name      = aws_lambda_function.iam_authed_agent.function_name
  authorization_type = "AWS_IAM"
}
# authorization_type = "NONE" alone does not prove public reachability -
# AWS's own docs state the function's resource-based policy must also
# grant public access, and none exists here. Isolates the two-resource
# requirement from the auth-type check itself.
resource "aws_lambda_function" "none_auth_no_permission" {
  function_name = "none-auth-no-permission"
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
resource "aws_lambda_function_url" "none_auth_no_permission" {
  function_name      = aws_lambda_function.none_auth_no_permission.function_name
  authorization_type = "NONE"
}
# A publicly invokable Lambda with no AI-service signal at all is real,
# but generic Lambda security already covered by general IaC scanners -
# out of scope the same way AGW-001 does not fire on a public method
# proxying to something other than Bedrock/SageMaker.
resource "aws_lambda_function" "public_no_ai_signal" {
  function_name = "public-no-ai-signal"
  role          = aws_iam_role.generic_lambda.arn
  runtime       = "python3.12"
  handler       = "app.handler"
}
resource "aws_lambda_function_url" "public_no_ai_signal" {
  function_name      = aws_lambda_function.public_no_ai_signal.function_name
  authorization_type = "NONE"
}
resource "aws_lambda_permission" "public_no_ai_signal_invoke" {
  statement_id           = "AllowPublicInvoke"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.public_no_ai_signal.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}
# authorization_type from a variable is unprovable, so it must not be
# flagged - the same rule every other check follows for interpolated
# values.
resource "aws_lambda_function" "variable_auth_agent" {
  function_name = "variable-auth-agent"
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
resource "aws_lambda_function_url" "variable_auth_agent" {
  function_name      = aws_lambda_function.variable_auth_agent.function_name
  authorization_type = var.function_url_auth_type
}
