# S3-CELEBROUS-UPDATED Project

This repository contains Terraform configurations to manage and deploy AWS S3 buckets using a modular structure. The project ensures flexibility and maintainability by separating configurations into modules and environment-specific files.

---

## File Structure

```plaintext
S3-CELEBROUS-UPDATED/
├── .gitignore              # Lists files and directories to be ignored by Git
├── Readme.md               # Documentation for the project
├── Archive/
│   ├── modules/
│   │   ├── s3/
│   │   │   ├── main.tf     # Core S3 module configurations
│   │   │   ├── outputs.tf  # Module outputs
│   │   │   ├── variables.tf# Module input variables
│   │   │   ├── versions.tf # Terraform version requirements
│   ├── policy/
│   │   ├── main.tf         # IAM policies for the project
│   ├── main.tf             # Root module
│   ├── outputs.tf          # Root module outputs
│   ├── providers.tf        # Providers configuration
│   ├── terraform.tfstate   # Terraform state file (generated after `apply`)
│   ├── terraform.tfvars    # Variables file (used to input project-specific values)
│   ├── variables.tf        # Input variables for the root module
│   ├── versions.tf         # Terraform version requirements
```

---

## Prerequisites

1. **Install Terraform:**
   - Download and install the latest version of Terraform from [Terraform Downloads](https://www.terraform.io/downloads).

2. **AWS CLI:**
   - Install and configure the AWS CLI with appropriate permissions.

   ```bash
   aws configure
   ```

3. **Git:**
   - Ensure Git is installed and properly set up.

4. **Access:**
   - Ensure your IAM user/role has the required permissions to manage S3 and IAM policies.

---

## Step-by-Step Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd s3-modules/PMI-S3-SETUP 
```

### 2. Initialize Terraform

```bash
terraform init
```

- This command downloads the required providers and initializes the backend.

### 3. Update Variables

- Modify the `terraform.tfvars` file to input environment-specific values. Example structure:

```hcl
bucket_name = "my-s3-bucket"
region      = "us-east-1"
enable_versioning = true
```

- If working on the S3 module specifically, you can also update `modules/s3/variables.tf`.

### 4. Validate Configuration

```bash
terraform validate
```

- Ensures the configuration files are syntactically valid.

### 5. Plan Deployment

```bash
terraform plan
```

- Shows a preview of the changes Terraform will make.

### 6. Apply Changes

```bash
terraform apply
```

- Deploys the infrastructure. You will be prompted to confirm the changes.

### 7. Push Changes to Repository

- Add and commit your changes:

```bash
git add .
git commit -m "Updated S3 bucket configuration"
git push origin main
```

---

## Editing the Code

### Root Module (`main.tf`, `outputs.tf`, `variables.tf`, etc.)

- Modify `main.tf` in the root directory for top-level configurations.
- Add new outputs in `outputs.tf` if you need to expose new resource attributes.
- Update `variables.tf` for new input variables.

### S3 Module

- Navigate to `modules/s3`.
- Edit `main.tf` for core S3 configurations.
- Add or update variables in `variables.tf` to customize bucket behavior.
- Specify new output attributes in `outputs.tf` if needed.

---

## Deployment Best Practices

1. **Use branches for feature development:**
   - Always create a new branch for changes.

   ```bash
   git checkout -b feature/my-new-feature
   ```

2. **Test your configuration locally:**
   - Run `terraform plan` and ensure changes are as expected.

3. **Use remote state for collaboration:**
   - Configure a backend in `providers.tf` to store the state remotely (e.g., S3).

4. **Code Review:**
   - Submit a pull request and ensure it is reviewed by a team member before merging.

---

## Troubleshooting

### Common Errors

1. **Error: No credentials found**
   - Ensure your AWS CLI is configured with valid credentials:

   ```bash
   aws configure
   ```

2. **Error: Bucket already exists**
   - Update `bucket_name` in `terraform.tfvars` to a unique name.

3. **Permission Denied Errors**
   - Verify your IAM role or user has the necessary permissions.

---

## Additional Resources

- [Terraform Documentation](https://www.terraform.io/docs)
- [AWS S3 Documentation](https://docs.aws.amazon.com/s3/index.html)

Feel free to reach out to the team if you encounter issues!
