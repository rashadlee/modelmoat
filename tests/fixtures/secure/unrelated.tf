resource "aws_s3_bucket" "email_archive" {
  bucket = "corp-email-archive"
  lifecycle_rule {
    enabled = true
    expiration {
      days = 365
    }
  }
}
resource "aws_s3_bucket" "html_assets" {
  bucket = "corp-html-assets"
}
resource "aws_db_instance" "legacy_mysql" {
  identifier          = "legacy-inventory-db"
  engine              = "mysql"
  publicly_accessible = true
}
