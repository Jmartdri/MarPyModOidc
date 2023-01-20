from MarPyModOidc.util import md5_hash
from mod_python import apache, Cookie
import time
from threading import Lock
import tempfile
import random
import os
import sys
import stat
import string
import contextlib

PY2 = sys.version[0] == "2"

if PY2:
    import anydbm as dbm
    from whichdb import whichdb
    from cPickle import loads, dumps
else:

    import dbm
    from dbm import whichdb
    from pickle import loads, dumps


tempdir = tempfile.gettempdir()
COOKIE_NAME = "sid"
CACHE_TTL = 60*5  # in second
CLEANUP_CHANCE = 5


def unlock_session_cleanup(sess):
    sess.unlock()


def isInt(value):
    try:
        int(value)
        return True
    except:
        return False


class BaseSession(dict):
    def __init__(self, req):

        self._mutex = Lock()
        self._req = req
        self._isnew = 0
        self._sid = 0
        self._csid = 0
        self._locked = 0
        self._ttl = 0

        dict.__init__(self)

        cookie = Cookie.get_cookie(req, COOKIE_NAME)
        # if cookie exist in req
        if cookie and cookie.value:
            self._sid = cookie.value

        if self._sid:
            self.lock()
            if not self.load():
                self._sid = 0
            self.unlock()

        if not self._sid:
            self.lock()
            self._sid = self.new_sid()
            self._ttl = int(time.time()) + CACHE_TTL
            self.save()
            Cookie.add_cookie(req, self.make_cookie())
            req.connection.notes['sid'] = self._sid
            self.unlock()
            self._isnew = 1
        else:
            self._isnew = 0

        if random.randint(1, CLEANUP_CHANCE) == 1:
            self.cleanup()

    def is_new(self):
        return not not self._isnew

    def id(self):
        return self._sid

    def make_cookie(self):
        c = Cookie.Cookie(COOKIE_NAME, self._sid)
        dirpath = self._req.hlist.directory
        if dirpath:
            docroot = self._req.document_root()
            c.path = dirpath[len(docroot):]
        else:
            c.path = '/'

        if not c.path or not self._req.uri.startswith(c.path):
            c.path = '/'
        return c

    def new_sid(self):
        result_str = ''.join(random.choice(string.ascii_letters)
                             for i in range(16))
        return md5_hash(result_str)

    def lock(self):
        self._mutex.acquire()
        self._locked = 1
        self._req.register_cleanup(unlock_session_cleanup, self)

    def unlock(self):
        if self._locked or self._mutex.locked():
            self._mutex.release()
            self._locked = 0

    def load(self):
        data = self.do_load()
        if not data:
            return 0
        elif self.corrupted(data):
            self.delete()
            return 0
        elif self.expired(data.get("__ttl__")):
            self.delete()
            return 0
        else:
            self._sid = data.get("__sid__")
            self._ttl = data.get("__ttl__")
            self.update(data.get("__data__"))
            return 1

    def corrupted(self, data):
        return (
            not isinstance(data, dict)
            or not isInt(data.get("__ttl__"))
            or not data.get("__sid__")
        )

    def expired(self, ttl=None):

        if ttl:
            return not isInt(ttl) or int(ttl) < int(time.time())
        else:
            return not isInt(self._ttl) or int(self._ttl) < int(time.time())

    def save(self):
        data = {"__data__": self.copy(), "__ttl__": self._ttl,
                "__sid__": self._sid}
        self.do_save(data)

    def delete(self):
        # self.do_delete()
        self.clear()

    def cleanup(self):
        self._do_cleanup()

    def __del__(self):
        self.unlock()

    def __str__(self):
        data = {
            'id': self._sid,
            'ttl': self._ttl,
            "is_new": not not self._isnew,
            "expired": self.expired()
        }
        data.update(self)
        return str(data)


def dbm_cleanup(param):
    filedbm, errLogCall = param
    try:
        with contextlib.closing(dbm.open(filedbm, 'w')) as db:
            for k in db.keys():
                try:
                    val = loads(db[k])
                    if not isInt(val.get("__ttl__")) or int(val.get("__ttl__")) < int(time.time()):
                        del db[k]
                except:
                    errLogCall("Error dbm Session : %s " % str(e))
    except Exception as e:
        errLogCall("Error dbm cleanup session : %s " % str(e))


class DbmSession(BaseSession):

    def __init__(self, req):

        opts = req.get_options()
        self._dbm_file = os.path.join(
            opts.get("session_directory", tempdir), "mr_session.dbm"
        )
        self._dbm_type = dbm

        BaseSession.__init__(self, req)

    def _set_dbm_type(self):
        module = whichdb(self._dbm_file)
        if module:
            self._dbm_type = __import__(module)

    def _get_dbm(self):
        result = self._dbm_type.open(
            self._dbm_file, "c", stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP
        )
        if self._dbm_type is dbm:
            self._set_dbm_type()
        return result

    def _do_cleanup(self):
        data = [self._dbm_file, self.log_error]
        self._req.register_cleanup(dbm_cleanup, data)
        self._req.log_error(
            "dbm session : registered database cleanup.", apache.APLOG_NOTICE
        )

    def do_load(self):
        dbm = self._get_dbm()
        try:
            if str(self._sid).encode() in dbm:
                return loads(dbm[self._sid.encode()])
            else:
                self._req.log_error("session id %s not in session cache " % self._sid,
                                    apache.APLOG_NOTICE)
                return None
        except Exception as e:
            self._req.log_error(
                "Error on loading session cache db : %s" % str(
                    e), apache.APLOG_ERR
            )
        finally:
            dbm.close()

    def do_save(self, dict):
        dbm = self._get_dbm()
        try:
            dbm[str(self._sid).encode()] = dumps(dict)
        except Exception as e:
            self._req.log_error(
                "Error on saving session cache db : %s" % str(e), apache.APLOG_ERR)
        finally:
            dbm.close()

    def do_delete(self):
        dbm = self._get_dbm()
        try:
            try:
                del dbm[str(self._sid).encode()]
            except KeyError:
                pass
        except Exception as e:
            self._req.log_error(
                "Error on cleaning session cache db : %s" % str(e), apache.APLOG_ERR)
        finally:
            dbm.close()

    def log_error(self, msg):
        self._req.log_error(msg, apache.APLOG_ERR)


def Session(req):
    return DbmSession(req)
