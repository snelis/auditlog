from unittest import TestCase

from django.http import HttpRequest

from audit_log.util import get_client_ip


class TestUtil(TestCase):

    def test_get_client_ip_forwarded(self):
        request = HttpRequest()
        request.META['HTTP_X_FORWARDED_FOR'] = '1.2.3.4'
        self.assertEqual(get_client_ip(request), '1.2.3.4')

    def test_get_client_ip(self):
        request = HttpRequest()
        request.META['REMOTE_ADDR'] = '2.3.4.5'
        self.assertEqual(get_client_ip(request), '2.3.4.5')

    def test_get_client_ip_exception(self):
        # todo: improve
        # This method causes the audit logger to perform a connect
        # which will run through the formatter, giving false positives about
        # our test coverage, and printing warnings along te way.
        with self.assertLogs(level='WARNING') as log:
            self.assertEqual(get_client_ip(request=None), 'failed to get ip')
            self.assertIn('Failed to get ip for audit log', log.output[0])
