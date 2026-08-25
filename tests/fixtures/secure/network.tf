resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type = "Interface"
}
resource "aws_vpc_endpoint" "sagemaker_runtime" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.us-east-1.sagemaker.runtime"
  vpc_endpoint_type = "Interface"
}
