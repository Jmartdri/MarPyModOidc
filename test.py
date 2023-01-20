import unittest
import unittest
from unittest.mock import patch, MagicMock


class TestSession(unittest.TestCase):

    def setUp(self):

        print(" ****** Running test method : %s *****  " %
              self._testMethodName)

        self.mock_apache = MagicMock()
        self.mock_session = MagicMock()
        self.mock_cookie = MagicMock()

        self.req_mock = MagicMock()
        self.req_mock.log_error = lambda msg, level: print(msg)
        self.req_mock.configure_mock(unparsed_uri="http://host:port/path/test")
        self.req_mock.get_options.return_value = {"session_directory": ""}
        self.cache_cookies = []

    def test_session_without_cookie(self):
        with patch.dict('sys.modules', {'mod_python': MagicMock(apache=self.mock_apache, Cookie=self.mock_cookie)}):

            from MarPyModOidc.session import DbmSession

            # cookie mocking
            cookiemock = MagicMock()
            cookiemock.configure_mock(value='')
            self.mock_cookie.get_cookie.return_value = cookiemock

            bs = DbmSession(self.req_mock)

            self.assertTrue(not not bs.id())

            self.cache_cookies.append(bs.id())

            print("Result : %s" % str(bs))

            self.test_session_after()

    def test_session_after(self):

        if not hasattr(self, 'cache_cookies') or not len(self.cache_cookies):
            self.skipTest(
                "test_init_new_session_with_cookie should run under test that generate cookie")

        with patch.dict('sys.modules', {'mod_python': MagicMock(apache=self.mock_apache, Cookie=self.mock_cookie)}):

            from MarPyModOidc.session import DbmSession

            # cookie mocking
            cookiemock = MagicMock()
            cookiemock.configure_mock(value=self.cache_cookies[0])
            self.mock_cookie.get_cookie.return_value = cookiemock

            bs = DbmSession(self.req_mock)
            self.cache_cookies.append(bs.id())

            print("Result : %s" % str(bs))

    def test_session_with_cookie(self):
        with patch.dict('sys.modules', {'mod_python': MagicMock(apache=self.mock_apache, Cookie=self.mock_cookie)}):

            from MarPyModOidc.session import DbmSession

            # cookie mocking
            cookiemock = MagicMock()
            cookiemock.configure_mock(value='aebe4f040bcd1e9c4cc0fb1c9b51ef0b')
            self.mock_cookie.get_cookie.return_value = cookiemock

            bs = DbmSession(self.req_mock)

            self.assertTrue(not not bs.id())

            self.cache_cookies.append(bs.id())

            print("Result : %s" % str(bs))

            self.test_session_after()
    
    def test_cleanup_cache_database(self):
        with patch.dict('sys.modules', {'mod_python': MagicMock(apache=self.mock_apache, Cookie=self.mock_cookie)}):
            from MarPyModOidc.session import dbm_cleanup
            
            errLog = lambda msg : print(msg)
            filedbm = "mr_session.dbm"
            dbm_cleanup([filedbm, errLog])


if __name__ == '__main__':
    unittest.main()
