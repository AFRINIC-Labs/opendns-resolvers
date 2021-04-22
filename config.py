from configparser import ConfigParser
import psycopg2


def config(filename='database.ini', section='postgresql'):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    return db


class DB():
    def __init__(self):
        self.params = config()
        self._connection = None
        self._cursor = None
        self.init()

    def connect(self):
        if not self._connection:
            try:
                self._connection = psycopg2.connect(**self.params)
                print('Connecting to the PostgreSQL database...')
                self._connection.autocommit = True
                return self._connection
            except (Exception, psycopg2.Error) as error:
                raise error

    def cursor(self):
        if not self._cursor or self._cursor.closed:
            if not self._connection:
                self.connect()
            self._cursor = self._connection.cursor()
            return self._cursor

    def execute(self, query):
        try:
            self._cursor.execute(query)
        except (Exception, psycopg2.Error) as error:
            raise error

    # Define Function to select data from DB
    def select(self, tablename: str):
        try:
            sql_statement1 = """SELECT * FROM {};""".format(tablename)
            self.execute(sql_statement1)
            #res = self._cursor.fetchall()
            res = self._cursor.fetchmany(5)
        except (Exception, psycopg2.Error) as error:
            raise error
        return res

    # Define Function to insert data into DB
    def insert(self, tablename: str, colums: list, data: list):
        try:
            datal = data.__str__().replace('[', '').replace(']', '')
            col = colums.__str__().replace('[', '').replace(']', '').replace("'", "")
            sql_statement = """INSERT INTO {} ({}) VALUES ({});""".format(tablename, col, datal)
            self.execute(sql_statement)
            return True
        except (Exception, psycopg2.Error) as error:
            raise error
            return False

    def close(self):
        if self._connection:
            if self._cursor:
                self._cursor.close()
            self._connection.close()
            print("PostgreSQL connection is closed")
        self._connection = None
        self._cursor = None

    def init(self):
        self.connect()
        self.cursor()
