resource "aws_comprehend_entity_recognizer" "exposed_recognizer" {
  name     = "exposed-recognizer"
  data_access_role_arn = aws_iam_role.comprehend.arn
  language_code = "en"
  input_data_config {
    entity_types {
      type = "PERSON"
    }
    documents {
      s3_uri = "s3://comprehend-training/documents/"
    }
  }
}
resource "aws_comprehend_document_classifier" "exposed_classifier" {
  name                  = "exposed-classifier"
  data_access_role_arn  = aws_iam_role.comprehend.arn
  language_code         = "en"
  input_data_config {
    s3_uri = "s3://comprehend-training/classifier/"
  }
}
