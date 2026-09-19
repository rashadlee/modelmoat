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

# The method itself requires AWS_IAM - looks safe in isolation - but the
# REST API's own resource policy independently allows Principal "*", which
# AWS's own docs confirm overrides that. Proves AGW-002 fires on the policy
# alone, independent of AGW-001's method-level check.
resource "aws_api_gateway_rest_api" "policy_api" {
  name = "policy-api"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowAnyPrincipal"
      Effect    = "Allow"
      Principal = "*"
      Action    = "execute-api:Invoke"
      Resource  = "*"
    }]
  })
}
resource "aws_api_gateway_resource" "policy_predict" {
  rest_api_id = aws_api_gateway_rest_api.policy_api.id
  parent_id   = aws_api_gateway_rest_api.policy_api.root_resource_id
  path_part   = "predict"
}
resource "aws_api_gateway_method" "policy_predict_post" {
  rest_api_id   = aws_api_gateway_rest_api.policy_api.id
  resource_id   = aws_api_gateway_resource.policy_predict.id
  http_method   = "POST"
  authorization = "AWS_IAM"
}
resource "aws_api_gateway_integration" "policy_predict_sagemaker" {
  rest_api_id             = aws_api_gateway_rest_api.policy_api.id
  resource_id             = aws_api_gateway_resource.policy_predict.id
  http_method             = aws_api_gateway_method.policy_predict_post.http_method
  integration_http_method = "POST"
  type                    = "AWS"
  uri                     = "arn:aws:apigateway:us-east-1:runtime.sagemaker:path/endpoints/prod-endpoint/invocations"
}

# Same defect reached through a separate aws_api_gateway_rest_api_policy
# resource instead of the inline policy attribute, exercising the other
# resolution path.
resource "aws_api_gateway_rest_api" "separate_policy_api" {
  name = "separate-policy-api"
}
resource "aws_api_gateway_rest_api_policy" "separate_policy_api" {
  rest_api_id = aws_api_gateway_rest_api.separate_policy_api.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowAnyPrincipal"
      Effect    = "Allow"
      Principal = "*"
      Action    = "execute-api:Invoke"
      Resource  = "*"
    }]
  })
}
resource "aws_api_gateway_resource" "separate_policy_predict" {
  rest_api_id = aws_api_gateway_rest_api.separate_policy_api.id
  parent_id   = aws_api_gateway_rest_api.separate_policy_api.root_resource_id
  path_part   = "predict"
}
resource "aws_api_gateway_method" "separate_policy_predict_post" {
  rest_api_id   = aws_api_gateway_rest_api.separate_policy_api.id
  resource_id   = aws_api_gateway_resource.separate_policy_predict.id
  http_method   = "POST"
  authorization = "AWS_IAM"
}
resource "aws_api_gateway_integration" "separate_policy_predict_bedrock" {
  rest_api_id             = aws_api_gateway_rest_api.separate_policy_api.id
  resource_id             = aws_api_gateway_resource.separate_policy_predict.id
  http_method             = aws_api_gateway_method.separate_policy_predict_post.http_method
  integration_http_method = "POST"
  type                    = "AWS"
  uri                     = "arn:aws:apigateway:us-east-1:bedrock-runtime:path/model/anthropic.claude-3-sonnet/invoke"
}
