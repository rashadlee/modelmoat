resource "aws_sagemaker_model" "exposed_llm" {
  name               = "exposed-llm"
  execution_role_arn = aws_iam_role.sm_exec.arn
  primary_container {
    image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/llm:latest"
  }
}
