resource "aws_s3_bucket" "email_archive" {
  bucket = "corp-email-archive"
}
resource "aws_db_instance" "legacy_mysql" {
  identifier          = "legacy-inventory-db"
  engine              = "mysql"
  publicly_accessible = true
}
