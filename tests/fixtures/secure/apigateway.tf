resource "aws_api_gateway_rest_api" "ml_api" {
  name = "ml-inference-api"
}

resource "aws_api_gateway_resource" "predict" {
  rest_api_id = aws_api_gateway_rest_api.ml_api.id
  parent_id   = aws_api_gateway_rest_api.ml_api.root_resource_id
  path_part   = "predict"
}

# Same SageMaker proxy target as the insecure fixture, but authorization
# requires IAM. The AI-service target alone is never the trigger.
resource "aws_api_gateway_method" "predict_post" {
  rest_api_id   = aws_api_gateway_rest_api.ml_api.id
  resource_id   = aws_api_gateway_resource.predict.id
  http_method   = "POST"
  authorization = "AWS_IAM"
}

resource "aws_api_gateway_integration" "predict_sagemaker" {
  rest_api_id             = aws_api_gateway_rest_api.ml_api.id
  resource_id             = aws_api_gateway_resource.predict.id
  http_method             = aws_api_gateway_method.predict_post.http_method
  integration_http_method = "POST"
  type                    = "AWS"
  uri                     = "arn:aws:apigateway:us-east-1:runtime.sagemaker:path/endpoints/prod-endpoint/invocations"
}

resource "aws_api_gateway_resource" "webhook" {
  rest_api_id = aws_api_gateway_rest_api.ml_api.id
  parent_id   = aws_api_gateway_rest_api.ml_api.root_resource_id
  path_part   = "webhook"
}

# Unauthenticated, but the integration is a Lambda proxy, not a direct AI
# service target - generic API security, out of modelmoat's lane, and must
# stay silent even though authorization is "NONE".
resource "aws_api_gateway_method" "webhook_post" {
  rest_api_id   = aws_api_gateway_rest_api.ml_api.id
  resource_id   = aws_api_gateway_resource.webhook.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "webhook_lambda" {
  rest_api_id             = aws_api_gateway_rest_api.ml_api.id
  resource_id             = aws_api_gateway_resource.webhook.id
  http_method             = aws_api_gateway_method.webhook_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.webhook_handler.invoke_arn
}

resource "aws_api_gateway_resource" "internal_predict" {
  rest_api_id = aws_api_gateway_rest_api.internal_api.id
  parent_id   = aws_api_gateway_rest_api.internal_api.root_resource_id
  path_part   = "predict"
}

# Unauthenticated and a genuine SageMaker proxy, but the REST API is PRIVATE,
# so internet reachability is not proven and the finding must stay silent.
resource "aws_api_gateway_rest_api" "internal_api" {
  name = "internal-ml-api"

  endpoint_configuration {
    types = ["PRIVATE"]
  }
}

resource "aws_api_gateway_method" "internal_predict_post" {
  rest_api_id   = aws_api_gateway_rest_api.internal_api.id
  resource_id   = aws_api_gateway_resource.internal_predict.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "internal_predict_sagemaker" {
  rest_api_id             = aws_api_gateway_rest_api.internal_api.id
  resource_id             = aws_api_gateway_resource.internal_predict.id
  http_method             = aws_api_gateway_method.internal_predict_post.http_method
  integration_http_method = "POST"
  type                    = "AWS"
  uri                     = "arn:aws:apigateway:us-east-1:runtime.sagemaker:path/endpoints/internal-endpoint/invocations"
}

resource "aws_api_gateway_resource" "from_variable" {
  rest_api_id = aws_api_gateway_rest_api.ml_api.id
  parent_id   = aws_api_gateway_rest_api.ml_api.root_resource_id
  path_part   = "from-variable"
}

# authorization from a variable is unprovable, so it must not be flagged -
# the same rule every other check follows for interpolated values.
resource "aws_api_gateway_method" "from_variable_post" {
  rest_api_id   = aws_api_gateway_rest_api.ml_api.id
  resource_id   = aws_api_gateway_resource.from_variable.id
  http_method   = "POST"
  authorization = var.method_authorization
}

resource "aws_api_gateway_integration" "from_variable_sagemaker" {
  rest_api_id             = aws_api_gateway_rest_api.ml_api.id
  resource_id             = aws_api_gateway_resource.from_variable.id
  http_method             = aws_api_gateway_method.from_variable_post.http_method
  integration_http_method = "POST"
  type                    = "AWS"
  uri                     = "arn:aws:apigateway:us-east-1:runtime.sagemaker:path/endpoints/prod-endpoint/invocations"
}
