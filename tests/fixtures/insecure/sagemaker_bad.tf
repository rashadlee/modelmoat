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
