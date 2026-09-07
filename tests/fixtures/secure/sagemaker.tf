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
resource "aws_sagemaker_domain" "studio" {
  domain_name              = "prod-studio"
  auth_mode                = "IAM"
  vpc_id                   = aws_vpc.main.id
  subnet_ids               = [aws_subnet.private_a.id]
  app_network_access_type  = "VpcOnly"
  default_user_settings {
    execution_role = aws_iam_role.sm_exec.arn
  }
}
# app_network_access_type from a variable is unprovable, so it must not be
# flagged - the same rule every other check follows for interpolated values.
resource "aws_sagemaker_domain" "from_variable" {
  domain_name              = "from-variable-studio"
  auth_mode                = "IAM"
  vpc_id                   = aws_vpc.main.id
  subnet_ids               = [aws_subnet.private_a.id]
  app_network_access_type  = var.app_network_access_type
  default_user_settings {
    execution_role = aws_iam_role.sm_exec.arn
  }
}
resource "aws_sagemaker_training_job" "hardened" {
  training_job_name = "prod-training-job"
  role_arn           = aws_iam_role.sm_exec.arn
  vpc_config {
    security_group_ids = [aws_security_group.sm.id]
    subnets            = [aws_subnet.private_a.id]
  }
  algorithm_specification {
    training_image     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/train:latest"
    training_input_mode = "File"
  }
  resource_config {
    instance_count    = 1
    instance_type     = "ml.g5.xlarge"
    volume_size_in_gb = 50
  }
  output_data_config {
    s3_output_path = "s3://acme-training-output/prod"
  }
  stopping_condition {
    max_runtime_in_seconds = 3600
  }
}
# Multiple instances (where enable_inter_container_traffic_encryption
# actually matters, unlike "hardened" above) with it explicitly enabled.
resource "aws_sagemaker_training_job" "distributed_encrypted" {
  training_job_name = "prod-distributed-training-job"
  role_arn           = aws_iam_role.sm_exec.arn
  vpc_config {
    security_group_ids = [aws_security_group.sm.id]
    subnets            = [aws_subnet.private_a.id]
  }
  enable_inter_container_traffic_encryption = true
  algorithm_specification {
    training_image     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/train:latest"
    training_input_mode = "File"
  }
  resource_config {
    instance_count    = 4
    instance_type     = "ml.g5.xlarge"
    volume_size_in_gb = 50
  }
  output_data_config {
    s3_output_path = "s3://acme-training-output/prod-distributed"
  }
  stopping_condition {
    max_runtime_in_seconds = 3600
  }
}
resource "aws_sagemaker_notebook_instance" "hardened" {
  name                    = "prod-notebook"
  role_arn                = aws_iam_role.sm_exec.arn
  instance_type           = "ml.t3.medium"
  direct_internet_access  = "Disabled"
  root_access             = "Disabled"
  subnet_id               = aws_subnet.private_a.id
  security_groups         = [aws_security_group.sm.id]
  kms_key_id              = aws_kms_key.sm.arn
}
# direct_internet_access from a variable is unprovable, so it must not be
# flagged - the same rule the Studio domain check above follows.
resource "aws_sagemaker_notebook_instance" "from_variable" {
  name                    = "from-variable-notebook"
  role_arn                = aws_iam_role.sm_exec.arn
  instance_type           = "ml.t3.medium"
  direct_internet_access  = var.direct_internet_access
  root_access             = "Disabled"
  subnet_id               = aws_subnet.private_a.id
  security_groups         = [aws_security_group.sm.id]
}
