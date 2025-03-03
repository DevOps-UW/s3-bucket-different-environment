terraform {
  backend "s3" {
    bucket = "011624006725-backed-pmi"
    key    = "tf-state/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
    profile = var.backend_profile
  }
}