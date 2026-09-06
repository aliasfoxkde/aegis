# Django settings committed with its development secrets.
DEBUG = True  # aegis:expect django-debug-print
ALLOWED_HOSTS = ["*"]

SECRET_KEY = "django-insecure-0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p"  # aegis:expect django-secret-key-hardcoded

DATABASE_PASSWORD = "pr0d-super-secret-42"  # aegis:expect hardcoded-password
