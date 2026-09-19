resource "aws_comprehend_entity_recognizer" "private_recognizer" {
  name                  = "prod-recognizer"
  data_access_role_arn  = aws_iam_role.comprehend.arn
  language_code         = "en"
  input_data_config {
    entity_types {
      type = "PERSON"
    }
    documents {
      s3_uri = "s3://comprehend-training/documents/"
    }
  }
  vpc_config {
    security_group_ids = [aws_security_group.comprehend.id]
    subnets             = [aws_subnet.private_a.id]
  }
}
resource "aws_comprehend_document_classifier" "private_classifier" {
  name                  = "prod-classifier"
  data_access_role_arn  = aws_iam_role.comprehend.arn
  language_code         = "en"
  input_data_config {
    s3_uri = "s3://comprehend-training/classifier/"
  }
  vpc_config {
    security_group_ids = [aws_security_group.comprehend.id]
    subnets             = [aws_subnet.private_a.id]
  }
}
