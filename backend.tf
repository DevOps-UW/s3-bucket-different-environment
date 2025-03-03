terraform {
  backend "s3" {
    bucket = "854473044844-backend"
    key    = "tf-state/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
    profile = "central-profile"
  }
}