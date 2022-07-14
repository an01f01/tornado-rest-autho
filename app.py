import os
import json
import ast
import datetime
import tornado.httpserver
import tornado.options
import tornado.ioloop
import tornado.web
import tornado.wsgi
from passlib.hash import pbkdf2_sha256

from tornado import gen, web, template

from queries import pool
import queries

import jwt

tornado.options.define('port', default='8000', help='REST API Port', type=int)

def encode_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365, seconds=0),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            os.environ['BOOKS_SECRET'],
            algorithm='HS256'
        )
    except Exception as e:
        return e

def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: { 'success': < 0 if sucess, otherwise < 0 is a fail >, 'user': <user name>, 'message': <message> }
    """
    try:
        payload = jwt.decode(auth_token, os.environ['BOOKS_SECRET'], algorithms=["HS256"])
        return { 'success': 0, 'user': payload['sub'], 'message': '' }
    except jwt.ExpiredSignatureError:
        return { 'success': -1, 'user': None, 'message': 'Signature expired. Please log in again.' }
    except jwt.InvalidTokenError:
        return { 'success': -2, 'user': None, 'message': 'Invalid token. Please log in again.' }

class BaseHandler(tornado.web.RequestHandler):
    """
    Base handler gonna to be used instead of RequestHandler
    """
    def write_error(self, status_code, **kwargs):
        if status_code in [403, 404, 500, 503]:
            self.write('Error %s' % status_code)
        else:
            self.write('BOOM!')

class ErrorHandler(tornado.web.ErrorHandler, BaseHandler):
    """
    Default handler gonna to be used in case of 404 error
    """
    pass

class BooksHandler(BaseHandler):

    def initialize(self):
        database_url = os.environ['BOOKS_DB_CONN']
        self.session = queries.TornadoSession(uri=database_url)

    """
    GET handler for fetching numbers from database
    """
    @gen.coroutine
    def get(self):
        auth_header = self.request.headers.get('Authorization')
        print(auth_header)
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        
        if auth_token:
            token = decode_auth_token(auth_token)
            print(token)
            if token['success'] == 0:
                try:
                    sql = "SELECT array_to_json(array_agg(row_to_json(json))) json FROM (SELECT bookid, title, book_info FROM books ORDER BY title) as json;"
                    results = yield self.session.query(sql, {})
                    data_ret = results.as_dict()
                    results.free()
                    print(data_ret)
                    self.set_status(200)
                    self.write({'message': 'All books sorted by title', 'books': data_ret['json']})
                    self.finish()
                except (queries.DataError, queries.IntegrityError) as error:
                    print(error)
                    self.set_status(500)
                    self.write({'message': 'Error getting books', 'books': [] })
                    self.finish()
            else:
                self.set_status(401)
                self.write({'status': 'fail', 'message': token['message'] })
                self.finish()
                return
        else:
            self.set_status(403)
            self.write({'status': 'fail', 'message': 'Invalid authentication token' })
            self.finish()
            return

    """
    POST handler for adding a new book to the database
    """
    @gen.coroutine   
    def post(self):

        auth_header = self.request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        
        if auth_token:
            book_json            = self.request.body.decode('utf-8')
            if (book_json == None or book_json == ''):
                self.set_status(200)
                self.write({'message': 'Book data is missing', 'book': {}})
                self.finish()
                return

            try:
                book_json = tornado.escape.json_decode(book_json)
            except (Exception) as e:
                self.set_status(500)
                self.write({'message': 'Error: Book data is not in valid JSON format', 'book': {} })
                self.finish()
                return

            token = decode_auth_token(auth_token)
            if token['success'] == 0:
                if 'title' not in book_json:
                    self.set_status(200)
                    self.write({'message': 'Error: book data is missing title, no book was created', 'book': {} })
                    self.finish()
                    return
                book_json['book_info'] = book_json.get('book_info', {})

                try:
                    sql = "INSERT INTO public.books(title, book_info) VALUES (%(book_title)s, %(book_info)s) RETURNING json_build_object('title', title, 'book_info', book_info);"
                    results = yield self.session.query(sql, {'book_title': book_json['title'], 'book_info': tornado.escape.json_encode(book_json['book_info'])})
                    data_ret = results.as_dict()
                    results.free()
                    self.set_status(201)
                    self.write({'message': 'Book added', 'book': data_ret['json_build_object']})
                    self.finish()
                except (queries.DataError, queries.IntegrityError) as error:
                    print(error)
                    self.set_status(500)
                    self.write({'message': 'Error: no book with that id exists', 'book': {} })
                    self.finish()
            else:
                self.set_status(401)
                self.write({'status': 'fail', 'message': token['message'] })
                self.finish()
                return
        else:
            self.set_status(403)
            self.write({'status': 'fail', 'message': 'Invalid authentication token' })
            self.finish()
            return

class BookHandler(BaseHandler):

    def initialize(self):
        database_url = os.environ['BOOKS_DB_CONN']
        self.session = queries.TornadoSession(uri=database_url)

    """
    GET handler for fetching numbers from database
    """
    @gen.coroutine
    def get(self, **params):
        auth_header = self.request.headers.get('Authorization')
        print(auth_header)
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        
        if auth_token:
            token = decode_auth_token(auth_token)
            if token['success'] == 0:
                try:
                    sql = "SELECT row_to_json(json) json FROM (SELECT bookid, title, book_info FROM books WHERE bookid = %(book_id)s) as json;"
                    results = yield self.session.query(sql, {'book_id': params['id']})
                    data_ret = results.as_dict()
                    results.free()
                    self.set_status(200)
                    self.write({'message': 'Book with id ' + params['id'], 'book': data_ret['json']})
                    self.finish()
                except (queries.DataError, queries.IntegrityError) as error:
                    print(error)
                    self.set_status(500)
                    self.write({'message': 'Error: no book with that id exists', 'book': {} })
                    self.finish()
            else:
                self.set_status(401)
                self.write({'status': 'fail', 'message': token['message'] })
                self.finish()
                return
        else:
            self.set_status(403)
            self.write({'status': 'fail', 'message': 'Invalid authentication token' })
            self.finish()
            return

class LogoutHandler(BaseHandler):
    
    def initialize(self):
        database_url = os.environ['BOOKS_DB_CONN']
        self.session = queries.TornadoSession(uri=database_url)

    """
    POST handler for user loggin
    """
    @gen.coroutine   
    def post(self):

        auth_header = self.request.headers.get('Authorization')
        print(auth_header)
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        
        if auth_token:
            token = decode_auth_token(auth_token)
            if token['success'] == 0:
                try:
                    sql = "SELECT COUNT(*) FROM blacklist_tokens WHERE token_str = %(token)s;"
                    results = yield self.session.query(sql, {'token': auth_token})
                    data_ret = results.as_dict()
                    results.free()
                    if (data_ret['count'] == 0):
                        sql = "INSERT INTO public.blacklist_tokens(token_str) VALUES (%(token)s) RETURNING blacklist_id;"
                        results = yield self.session.query(sql, {'token': auth_token})
                        data_ret = results.as_dict()
                        results.free()
                        self.set_status(201)
                        self.write({'status': 'success', 'message': 'Successfully logged out' })
                        self.finish()
                    else:
                        self.set_status(200)
                        self.write({'status': 'success', 'message': 'Token is already invalid' })
                        self.finish()
                except (queries.DataError, queries.IntegrityError) as error:
                    self.set_status(200)
                    self.write({'status': 'fail', 'message': error})
                    self.finish()
            else:
                self.set_status(401)
                self.write({'status': 'fail', 'message': token['message'] })
                self.finish()
                return
        else:
            self.set_status(403)
            self.write({'status': 'fail', 'message': 'Invalid authentication token' })
            self.finish()
            return
         
class LoginHandler(BaseHandler):
    
    def initialize(self):
        database_url = os.environ['BOOKS_DB_CONN']
        self.session = queries.TornadoSession(uri=database_url)

    """
    POST handler for user loggin
    """
    @gen.coroutine   
    def post(self):

        data_json = json.loads(self.request.body)
        try:
            username = data_json.get("username")
            password = data_json.get("password")

            sql = "SELECT username, pwd FROM users WHERE username = %(user)s;"
            results = yield self.session.query(sql, {'user': username})
            data_ret = results.as_dict()
            results.free()

            if pbkdf2_sha256.verify(password, data_ret['pwd']): 
                auth_token = encode_auth_token(username)
                self.set_status(200)
                self.write({'status': 'success', 'message': 'Logged in successfully', 'auth_token': auth_token })
                self.finish()
                return
            else:
                self.set_status(500)
                self.write({'status': 'fail', 'message': 'Invalid loggin attempt' })
                self.finish()
                return

        except:
            self.set_status(500)
            self.write({'status': 'fail', 'message': 'Invalid loggin attempt' })
            self.finish()
            return

def make_app():
    settings = dict(
        cookie_secret=str(os.urandom(45)),
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        default_handler_class=ErrorHandler,
        default_handler_args=dict(status_code=404)
    )
    return tornado.web.Application([
        (r"/api/login", LoginHandler),
        (r"/api/logout", LogoutHandler),
        (r"/api/books", BooksHandler),
        (r"/api/book/(?P<id>[^\/]+)", BookHandler),
        ], **settings)

def main():
    app = make_app()
    return app

app = main()

if __name__ == '__main__':
    print("starting tornado server..........")
    app.listen(tornado.options.options.port)
    tornado.ioloop.IOLoop.current().start()
