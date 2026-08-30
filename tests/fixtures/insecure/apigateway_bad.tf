resource "aws_api_gateway_rest_api" "ml_api" {
  name = "ml-inference-api"
}

resource "aws_api_gateway_resource" "predict" {
  rest_api_id = aws_api_gateway_rest_api.ml_api.id
  parent_id   = aws_api_gateway_rest_api.ml_api.root_resource_id
  path_part   = "predict"
}

resource "aws_api_gateway_method" "predict_post" {
  rest_api_id   = aws_api_gateway_rest_api.ml_api.id
  resource_id   = aws_api_gateway_resource.predict.id
  http_method   = "POST"
  authorization = "NONE"
}

# http_method references the method's own attribute - the idiomatic
# Terraform form - so modelmoat resolves the target method through that
# reference rather than the (rest_api_id, resource_id, http_method) triple.
resource "aws_api_gateway_integration" "predict_sagemaker" {
  rest_api_id             = aws_api_gateway_rest_api.ml_api.id
  resource_id             = aws_api_gateway_resource.predict.id
  http_method             = aws_api_gateway_method.predict_post.http_method
  integration_http_method = "POST"
  type                    = "AWS"
  uri                     = "arn:aws:apigateway:us-east-1:runtime.sagemaker:path/endpoints/prod-endpoint/invocations"
}

resource "aws_api_gateway_resource" "invoke" {
  rest_api_id = aws_api_gateway_rest_api.ml_api.id
  parent_id   = aws_api_gateway_rest_api.ml_api.root_resource_id
  path_part   = "invoke"
}

resource "aws_api_gateway_method" "invoke_post" {
  rest_api_id   = aws_api_gateway_rest_api.ml_api.id
  resource_id   = aws_api_gateway_resource.invoke.id
  http_method   = "POST"
  authorization = "NONE"
}

# Same shape, but http_method is a literal on both sides, exercising the
# (rest_api_id, resource_id, http_method) triple match instead of the
# reference shortcut above.
resource "aws_api_gateway_integration" "invoke_bedrock" {
  rest_api_id             = aws_api_gateway_rest_api.ml_api.id
  resource_id             = aws_api_gateway_resource.invoke.id
  http_method             = "POST"
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = "arn:aws:apigateway:us-east-1:bedrock-runtime:path/model/anthropic.claude-3-sonnet/invoke"
}

resource "aws_api_gateway_resource" "agent" {
  rest_api_id = aws_api_gateway_rest_api.ml_api.id
  parent_id   = aws_api_gateway_rest_api.ml_api.root_resource_id
  path_part   = "agent"
}

resource "aws_api_gateway_method" "agent_post" {
  rest_api_id   = aws_api_gateway_rest_api.ml_api.id
  resource_id   = aws_api_gateway_resource.agent.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "agent_bedrock_agent" {
  rest_api_id             = aws_api_gateway_rest_api.ml_api.id
  resource_id             = aws_api_gateway_resource.agent.id
  http_method             = aws_api_gateway_method.agent_post.http_method
  integration_http_method = "POST"
  type                    = "AWS"
  uri                     = "arn:aws:apigateway:us-east-1:bedrock-agent-runtime:path/agents/ABCDEFGH/agentAliases/TSTALIASID/sessions/test-session/text"
}
