resource "aws_sagemaker_model" "exposed_llm" {
  name               = "exposed-llm"
  execution_role_arn = aws_iam_role.sm_exec.arn
  primary_container {
    image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/llm:latest"
  }
}
resource "aws_sagemaker_domain" "unset_access_type" {
  domain_name = "exposed-studio-unset"
  auth_mode   = "IAM"
  vpc_id      = aws_vpc.main.id
  subnet_ids  = [aws_subnet.private_a.id]
  default_user_settings {
    execution_role = aws_iam_role.sm_exec.arn
  }
}
resource "aws_sagemaker_domain" "explicit_public" {
  domain_name              = "exposed-studio-public"
  auth_mode                = "IAM"
  vpc_id                   = aws_vpc.main.id
  subnet_ids               = [aws_subnet.private_a.id]
  app_network_access_type  = "PublicInternetOnly"
  default_user_settings {
    execution_role = aws_iam_role.sm_exec.arn
  }
}
resource "aws_sagemaker_training_job" "exposed_training" {
  training_job_name = "exposed-training-job"
  role_arn           = aws_iam_role.sm_exec.arn
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
    s3_output_path = "s3://acme-training-output/exposed"
  }
  stopping_condition {
    max_runtime_in_seconds = 3600
  }
}
# vpc_config present (unlike exposed_training above), isolating this fixture
# to the inter-container-traffic-encryption finding specifically - proves
# the two findings are independent, the same shape as the notebook's
# explicit_open_notebook case.
resource "aws_sagemaker_training_job" "distributed_unencrypted" {
  training_job_name = "distributed-unencrypted-job"
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
    instance_count    = 4
    instance_type     = "ml.g5.xlarge"
    volume_size_in_gb = 50
  }
  output_data_config {
    s3_output_path = "s3://acme-training-output/distributed"
  }
  stopping_condition {
    max_runtime_in_seconds = 3600
  }
}
resource "aws_sagemaker_notebook_instance" "exposed_notebook" {
  name          = "exposed-notebook"
  role_arn      = aws_iam_role.sm_exec.arn
  instance_type = "ml.t3.medium"
}
# direct_internet_access set explicitly (not just left absent), with
# root_access explicitly turned off, so this fixture also proves the two
# findings are independent - only the network one should fire here.
resource "aws_sagemaker_notebook_instance" "explicit_open_notebook" {
  name                  = "explicit-open-notebook"
  role_arn              = aws_iam_role.sm_exec.arn
  instance_type         = "ml.t3.medium"
  direct_internet_access = "Enabled"
  root_access            = "Disabled"
}
