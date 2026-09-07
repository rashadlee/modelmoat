resource "aws_sagemaker_model_package_group" "private" {
  model_package_group_name = "prod-private-registry"
}

resource "aws_sagemaker_model_package_group" "scoped" {
  model_package_group_name = "prod-scoped-registry"
}
resource "aws_sagemaker_model_package_group_policy" "scoped" {
  model_package_group_name = aws_sagemaker_model_package_group.scoped.model_package_group_name
  resource_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SpecificTrustedAccountOnly"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::111122223333:root"
      }
      Action   = ["sagemaker:DescribeModelPackage", "sagemaker:ListModelPackages"]
      Resource = [aws_sagemaker_model_package_group.scoped.arn]
    }]
  })
}

# resource_policy from a variable is unprovable, so it must not be flagged -
# the same rule every other policy-driven check in this project follows.
resource "aws_sagemaker_model_package_group" "from_variable" {
  model_package_group_name = "from-variable-registry"
}
resource "aws_sagemaker_model_package_group_policy" "from_variable" {
  model_package_group_name = aws_sagemaker_model_package_group.from_variable.model_package_group_name
  resource_policy           = var.model_registry_policy
}
