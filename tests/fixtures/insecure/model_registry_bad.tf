resource "aws_sagemaker_model_package_group" "public_registry" {
  model_package_group_name = "public-registry"
}
resource "aws_sagemaker_model_package_group_policy" "public_registry" {
  model_package_group_name = aws_sagemaker_model_package_group.public_registry.model_package_group_name
  resource_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AnyAccount"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["sagemaker:DescribeModelPackage", "sagemaker:ListModelPackages"]
      Resource  = [aws_sagemaker_model_package_group.public_registry.arn]
    }]
  })
}

# Same defect reached through a data.aws_iam_policy_document reference
# instead of inline jsonencode, exercising the other resolution path.
data "aws_iam_policy_document" "public_registry_via_data_source" {
  statement {
    sid     = "AnyAccountViaDataSource"
    effect  = "Allow"
    actions = ["sagemaker:DescribeModelPackage", "sagemaker:ListModelPackages"]
    principals {
      identifiers = ["*"]
      type        = "AWS"
    }
  }
}
resource "aws_sagemaker_model_package_group" "public_via_data_source" {
  model_package_group_name = "public-via-data-source"
}
resource "aws_sagemaker_model_package_group_policy" "public_via_data_source" {
  model_package_group_name = aws_sagemaker_model_package_group.public_via_data_source.model_package_group_name
  resource_policy           = data.aws_iam_policy_document.public_registry_via_data_source.json
}
