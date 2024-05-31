# S3 Sensitive Information Scanner

This Python script scans readable files in AWS S3 buckets for sensitive information such as passwords, keys, and access tokens. It supports various file types including `.txt`, `.docx`, `.xlsx`, `.csv`, `.json`, etc.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/dazzyddos/aws_s3_scanner.git
    cd aws_s3_scanner
    ```

2. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Ensure your AWS credentials are configured `aws configure`. You can also do this by setting environment variables or using the AWS credentials file.

2. Usage:
   To scan specific buckets:
```bash
python s3_scanner.py -b bucket1 bucket2
```
   To scan all accessible buckets:
```bash
python s3_scanner.py
```
## Example Output

![](https://raw.githubusercontent.com/dazzyddos/aws_s3_scanner/main/s3scan.png)

## File Types Supported

- Text files (`.txt`)
- Word documents (`.docx`)
- Excel spreadsheets (`.xlsx`)
- CSV files (`.csv`)
- JSON files (`.json`)
- XML files (`.xml`)
- YAML files (`.yaml`, `.yml`)
- INI configuration files (`.ini`)
- SQL files (`.sql`)
