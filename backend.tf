terraform {
  backend "s3" {
    bucket = "854473044844-myaws-s3"
    key    = "tf-state/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
  }
}