resource "aws_sagemaker_model" "llm" {
  name                     = "prod-llm-model"
  execution_role_arn       = aws_iam_role.sm_exec.arn
  enable_network_isolation = true
  vpc_config {
    security_group_ids = [aws_security_group.sm.id]
    subnets            = [aws_subnet.private_a.id]
  }
  primary_container {
    image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/llm:latest"
  }
}
resource "aws_sagemaker_endpoint_configuration" "llm" {
  name        = "prod-llm-endpoint-config"
  kms_key_arn = aws_kms_key.sm.arn
  production_variants {
    variant_name           = "primary"
    model_name             = aws_sagemaker_model.llm.name
    instance_type          = "ml.g5.xlarge"
    initial_instance_count = 1
  }
}
resource "aws_sagemaker_endpoint" "llm" {
  name                 = "prod-llm"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.llm.name
}
