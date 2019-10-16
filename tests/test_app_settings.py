from django.conf import settings
from django.test import TestCase


class TestSettings(TestCase):

    def test_valid_settings(self):
        self.assertEqual(settings.AUDIT_LOG_APP_NAME, 'test', 'AUDIT_LOG_APP_NAME has unexpected value')

    def test_host_setting_type(self):
        self.assertEqual(type(settings.AUDIT_LOG_LOGSTASH_PORT), int, 'AUDIT_LOG_LOGSTASH_PORT should be an integer')

    def test_missing_app_name(self):
        # todo
        # Test that an ImproperlyConfigured exception is raised when AUDIT_LOG_APP_NAME is missing
        pass

    def test_missing_logstash_host(self):
        # todo
        # Test that an ImproperlyConfigured exception is raised when AUDIT_LOG_LOGSTASH_HOST is missing
        pass

    def test_missing_logstash_port(self):
        # todo
        # Test that an ImproperlyConfigured exception is raised when AUDIT_LOG_LOGSTASH_PORT is missing
        pass
