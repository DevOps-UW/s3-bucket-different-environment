terraform {
  backend "s3" {
    bucket = "pmi-terraform-state-test"
    key    = "pmi-tf-state/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
  }
}