# PMI-S3-SETUP/PMI-S3-SETUP/README.md

# PMI S3 Setup Project

This project is designed to manage S3 bucket configurations across multiple AWS accounts using Terraform. It includes separate environments for different accounts: PMI, BBQ, and MTI.

## Project Structure

```
PMI-S3-SETUP
├── .github
│   └── workflows
│       └── deploy.yml
├── environments
│   ├── pmi
│   │   └── main.tf
│   ├── bbq
│   │   └── main.tf
│   └── mti
│       └── main.tf
├── modules
│   └── s3
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
├── README.md
└── terraform.tfvars
```

## Environment Setup

Each environment folder contains a `main.tf` file that defines the Terraform configuration specific to that AWS account. 

- **PMI Environment**: Located in `environments/pmi/main.tf`
- **BBQ Environment**: Located in `environments/bbq/main.tf`
- **MTI Environment**: Located in `environments/mti/main.tf`

## S3 Module

The S3 module is located in the `modules/s3` directory and includes:

- `main.tf`: Resource definitions for creating S3 buckets.
- `variables.tf`: Input variables for customizing S3 bucket properties.
- `outputs.tf`: Output values from the S3 module.

## GitHub Actions

The project includes a GitHub Actions workflow defined in `.github/workflows/deploy.yml`. This workflow automates the process of initializing, planning, and applying Terraform configurations across the different environments whenever changes are made to the repository.

## Usage

1. Clone the repository.
2. Navigate to the desired environment folder (e.g., `environments/pmi`).
3. Run `terraform init` to initialize the Terraform configuration.
4. Run `terraform plan` to see the changes that will be applied.
5. Run `terraform apply` to apply the changes.

## Variables

The `terraform.tfvars` file contains variable definitions that allow for easy configuration of environment-specific values. Modify this file as needed for your specific AWS account settings.

## Contributing

Feel free to submit issues or pull requests for improvements or bug fixes.