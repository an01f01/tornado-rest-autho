import os
import sys
import tornado.options
import tornado.ioloop
import tornado.web
import random
import math
import json
from passlib.hash import pbkdf2_sha256
    
from queries import pool
import queries


if __name__ == "__main__":

    print("setting up csv string")
    csvString = 'Username,Password\n'

    print('Generating accounts...')
    database_url = os.environ['BOOKS_DB_CONN']
    session = queries.Session(uri=database_url)

    n = 5
    print(' - creating {0} user accounts...'.format(n))
    try:
        for i in range(5):
            username = 'bookuser' + '{0:03d}'.format(i+1)
            pchars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
            password = ''.join(random.choice(pchars) for c in range(8))
            hashcode = pbkdf2_sha256.hash(password)
        
            sql = "INSERT INTO public.users(username, pwd) VALUES (%(user)s, %(pwd)s) RETURNING username;"
            results = session.query(sql, {'user': username, 'pwd': hashcode})
            data_ret = results.as_dict()
            print(data_ret)
            results.free()
            csvString += '{0},{1}\n'.format(username, password)

    except (queries.DataError, queries.IntegrityError) as error:
        print(error)
        
    f = open("booksdb_users.csv", "w+")
    f.write(csvString)
    f.close()
