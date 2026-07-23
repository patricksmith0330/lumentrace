import os
import tempfile


TEST_DATA_DIR = tempfile.mkdtemp(prefix='lumentrace-tests-')
os.environ.setdefault('SECRET_KEY', 'django-test-secret-that-is-not-used-in-production')
os.environ.setdefault('DATA_DIR', TEST_DATA_DIR)
os.environ.setdefault('DATABASE_PATH', os.path.join(TEST_DATA_DIR, 'lumentrace.db'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'lumentrace.settings')
os.environ.setdefault('START_MONITORING', '0')
