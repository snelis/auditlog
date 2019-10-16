from django.contrib.auth.models import Group, User
from django.http import HttpResponse
from django.test import RequestFactory, TestCase
from django.views import View

from audit_log.log.logger import AuditLog


class TestLogger(TestCase):

    def setUp(self):
        self.request_factory = RequestFactory()

    def test_empty_on_create(self):
        log = AuditLog()
        self.assertIsNone(log.app)
        self.assertIsNone(log.http_request)
        self.assertIsNone(log.http_response)
        self.assertIsNone(log.user)
        self.assertIsNone(log.filter)
        self.assertIsNone(log.results)

    def test_set_app_name(self):
        log = AuditLog()
        log.set_app_name('test')
        self.assertEqual(log.app['name'], 'test')

    def test_set_http_request(self):
        log = AuditLog()
        request = self.request_factory.get("/",  SERVER_NAME="localhost", HTTP_USER_AGENT='test_agent')
        log.set_http_request(request)

        self.assertEqual(log.http_request['method'], 'GET')
        self.assertEqual(log.http_request['url'], 'http://localhost/')
        self.assertEqual(log.http_request['user_agent'], 'test_agent')

    def test_set_http_response(self):
        log = AuditLog()
        request = self.request_factory.get('/')
        response = View.as_view()(request)
        log.set_http_response(response)

        self.assertEqual(log.http_response['status_code'], 405)
        self.assertEqual(log.http_response['reason'], 'Method Not Allowed')
        self.assertTrue('Allow' in log.http_response['headers'])
        self.assertTrue('Content-Type' in log.http_response['headers'])

    def test_set_user_from_request(self):
        user = User.objects.create_user(username='username', email='username@host.com')
        group, _ = Group.objects.get_or_create(name='testgroup')
        group.user_set.add(user)

        request = self.request_factory.get("/")
        request.user = user

        log = AuditLog()
        log.set_user_from_request(request, realm='testrealm')

        self.assertEqual(log.user['authenticated'], True)
        self.assertEqual(log.user['provider']['name'], '')
        self.assertEqual(log.user['provider']['realm'], 'testrealm')
        self.assertEqual(log.user['email'], 'username@host.com')
        self.assertEqual(log.user['roles'], ['testgroup'])
        self.assertEqual(log.user['ip'], '127.0.0.1')

    def test_set_user(self):
        log = AuditLog()
        log.set_user(
            authenticated=True, provider='test', email='username@host.com',
            roles=['role1', 'role2'], ip='12.23.34.45', realm='testrealm'
        )

        self.assertEqual(log.user['authenticated'], True)
        self.assertEqual(log.user['provider']['name'], 'test')
        self.assertEqual(log.user['provider']['realm'], 'testrealm')
        self.assertEqual(log.user['email'], 'username@host.com')
        self.assertEqual(log.user['roles'], ['role1', 'role2'])
        self.assertEqual(log.user['ip'], '12.23.34.45')

    def test_set_filter(self):
        log = AuditLog()
        log.set_filter(object_name='objname', fields='fields', terms='terms')
        self.assertEqual(log.filter['object'], 'objname')
        self.assertEqual(log.filter['fields'], 'fields')
        self.assertEqual(log.filter['terms'], 'terms')

    def test_set_results(self):
        log = AuditLog()
        test_results = [
            'There are the results',
            ['this', 'is', 'a', 'list'],
            {'this': 'is', 'a': 'dict'},
            123
        ]
        for results in test_results:
            log.set_results(results)
            self.assertEqual(log.results, results)

    def test_extras_app_name(self):
        log = AuditLog()
        log.set_app_name('test')

        extras = log.get_extras(log_type='test')
        self.assertIn('app', extras)
        self.assertEqual(extras['app']['name'], 'test')

    def test_extras_http_request(self):
        log = AuditLog()
        request = self.request_factory.get("/", SERVER_NAME="localhost", HTTP_USER_AGENT='test_agent')
        log.set_http_request(request)

        extras = log.get_extras(log_type='test')
        self.assertIn('http_request', extras)
        self.assertEqual(extras['http_request']['method'], 'GET')
        self.assertEqual(extras['http_request']['url'], 'http://localhost/')
        self.assertEqual(extras['http_request']['user_agent'], 'test_agent')

    def test_extras_http_response(self):
        log = AuditLog()
        request = self.request_factory.get('/')
        response = View.as_view()(request)
        log.set_http_response(response)

        extras = log.get_extras(log_type='test')
        self.assertIn('http_response', extras)
        self.assertEqual(extras['http_response']['status_code'], 405)
        self.assertEqual(extras['http_response']['reason'], 'Method Not Allowed')

        # TODO: improve: mock http response so we know exactly what headers are present
        self.assertIn('Allow', extras['http_response']['headers'])
        self.assertIn('Content-Type', extras['http_response']['headers'])

    def test_extras_user_from_request(self):
        user = User.objects.create_user(username='username', email='username@host.com')
        group, _ = Group.objects.get_or_create(name='testgroup')
        group.user_set.add(user)

        request = self.request_factory.get("/")
        request.user = user

        log = AuditLog()
        log.set_user_from_request(request, realm='testrealm')

        extras = log.get_extras(log_type='test')
        self.assertIn('user', extras)
        self.assertEqual(extras['user']['authenticated'], True)
        self.assertEqual(extras['user']['provider']['name'], '')
        self.assertEqual(extras['user']['provider']['realm'], 'testrealm')
        self.assertEqual(extras['user']['email'], 'username@host.com')
        self.assertEqual(extras['user']['roles'], ['testgroup'])
        self.assertEqual(extras['user']['ip'], '127.0.0.1')

    def test_extras_user(self):
        log = AuditLog()
        log.set_user(
            authenticated=True, provider='test', email='username@host.com',
            roles=['role1', 'role2'], ip='12.23.34.45', realm='testrealm'
        )

        extras = log.get_extras(log_type='test')
        self.assertIn('user', extras)
        self.assertEqual(extras['user']['authenticated'], True)
        self.assertEqual(extras['user']['provider']['name'], 'test')
        self.assertEqual(extras['user']['provider']['realm'], 'testrealm')
        self.assertEqual(extras['user']['email'], 'username@host.com')
        self.assertEqual(extras['user']['roles'], ['role1', 'role2'])
        self.assertEqual(extras['user']['ip'], '12.23.34.45')

    def test_extras_filter(self):
        log = AuditLog()
        log.set_filter(object_name='objname', fields='fields', terms='terms')

        extras = log.get_extras(log_type='test')
        self.assertIn('filter', extras)
        self.assertEqual(extras['filter']['object'], 'objname')
        self.assertEqual(extras['filter']['fields'], 'fields')
        self.assertEqual(extras['filter']['terms'], 'terms')

    def test_extras_results(self):
        log = AuditLog()
        test_results = [
            'There are the results',
            ['this', 'is', 'a', 'list'],
            {'this': 'is', 'a': 'dict'},
            123
        ]
        for results in test_results:
            log.set_results(results)
            extras = log.get_extras(log_type='test')
            self.assertIn('results', extras)
            self.assertEqual(extras['results'], results)

    def test_extras_logtype(self):
        log = AuditLog()
        extras = log.get_extras(log_type='test_type')
        self.assertEqual(extras['type'], 'test_type')

    def test_send_log_info(self):
        # TODO implement after refactoring
        pass

        # expected_log_output = {
        #     'app': None,
        #     'http_request': None,
        #     'http_response': None,
        #     'user': None,
        #     'filter': None,
        #     'results': None,
        #     'type': 'info'
        # }
        #
        # log = AuditLog()
        # with self.assertLogs(logger=app_settings.AUDIT_LOG_LOGGER_NAME) as mocked_logger:
        #     log.info("message").send_log()
        #     self.assertEqual(mocked_logger.output, expected_log_output)

    def test_get_headers_from_response(self):
        expected_headers = {
            'Header1': 'value1',
            'Header2': 'value2',
            'Header3': 'value3'
        }
        response = HttpResponse()
        for header, value in expected_headers.items():
            response.__setitem__(header, value)

        headers = AuditLog()._get_headers_from_response(response)

        # Assert that the header we put in, will come out.
        # Note that the HttpResponse class will add a default header
        # 'content-type'.
        for header, expected_value in expected_headers.items():
            self.assertEqual(headers[header], expected_value)
