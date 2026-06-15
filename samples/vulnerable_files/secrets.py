# Intentionally vulnerable Python file for testing hardcoded secrets
# This file contains high-entropy API keys and passwords

# Vulnerable: hardcoded API Key
OPENAI_API_KEY = "sk-proj-4A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U"

# Vulnerable: hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Vulnerable: hardcoded database password
DB_PASS = "admin_super_secret_password_2026_xyz"

# Vulnerable: hardcoded token
AUTH_TOKEN = "jwt_token_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
