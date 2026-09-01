"""
Configuration module containing secrets and environment setup
"""

# Hardcoded DB credentials & keys
db_password = "ProductionDbSecretPassword99"
api_key = "ak_live_9876543210abcdef01234567"
jwt_secret = "my_ultra_secret_signing_key_2026"

# System storage paths
UPLOAD_DIR = "/var/data/uploads"
LOG_FILE = "/var/log/app/server.log"
BACKUP_DIR = "/opt/backups"
