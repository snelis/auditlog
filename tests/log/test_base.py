import logging

from django.test import TestCase

from audit_log.log.base import BaseLog


class TestBaseLog(TestCase):

    def test_default_log_level(self):
        baselog = BaseLog()
        self.assertEqual(baselog.level, logging.INFO)
        self.assertEqual(baselog.message, '')

    def test_debug(self):
        baselog = BaseLog()
        baselog.debug('test')
        self.assertEqual(baselog.level, logging.DEBUG)
        self.assertEqual(baselog.message, 'test')

    def test_info(self):
        baselog = BaseLog()
        baselog.info('test')
        self.assertEqual(baselog.level, logging.INFO)
        self.assertEqual(baselog.message, 'test')

    def test_warning(self):
        baselog = BaseLog()
        baselog.warning('test')
        self.assertEqual(baselog.level, logging.WARNING)
        self.assertEqual(baselog.message, 'test')

    def test_error(self):
        baselog = BaseLog()
        baselog.error('test')
        self.assertEqual(baselog.level, logging.ERROR)
        self.assertEqual(baselog.message, 'test')

    def test_critical(self):
        baselog = BaseLog()
        baselog.critical('test')
        self.assertEqual(baselog.level, logging.CRITICAL)
        self.assertEqual(baselog.message, 'test')
