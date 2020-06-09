import sqlite3

class Users:
    def __init__(self, tablename="users", userId = "userId", password="password", username="username", connected="connected"):
        self.__tablename = tablename
        self.__userId = userId
        self.__password = password
        self.__username = username
        self.__connected = connected
        conn = sqlite3.connect('test4.db')
        print("Opened database successfully");
        str = "CREATE TABLE IF NOT EXISTS " + tablename +\
              "(" + self.__userId + " " + " TEXT PRIMARY KEY,"
        str += " " + self.__username + " TEXT PRIMARY KEY,"
        str += " " + self.__password + " TEXT PRIMARY KEY)"
        conn.execute(str)
        print("Table created successfully");
        conn.commit()
        conn.close()

    def log_in(self, userId, username, password):
        try:
            conn = sqlite3.connect('test4.db')
            str1 = "select*from users"
            print(str1)
            cursor = conn.execute(str1)
            if self.check_if_exist(userId):
                for row in cursor:
                    if (str(row[0]) == str(userId)) and (row[1] == username) and (row[2] == password):
                        print("loged in seccessfully")
                        return True
                return False
        except:
            return False
            print("user not found")


       # print("Operation done successfully");
        #conn.close()

    def check_if_exist(self, userId):
        try:
            conn = sqlite3.connect('test4.db')
            str1 = "SELECT userId FROM users WHERE userId= "+str(userId)
            cur = conn.execute(str1)
            for row in cur.fetchall():
                print(str(row[0]))
                if (str(userId )== row[0]):
                    return True
            return False
        except:
            return False

    def return_values(self, userId):
        try:
            conn = sqlite3.connect('test4.db')
            str1 = "SELECT userId, username, password  from " + self.__tablename + " where " + self.__userId + "=" + str(userId)
            cursor = conn.execute(str1)
            for row in cursor:
                return row[1], row[2]
        except:
            print("not")

    def sign_up(self, userId, username, password):
        try:
            conn = sqlite3.connect('test4.db')
            str1 = "select*from users"
            cursor = conn.execute(str1)
            for row in cursor:
                if (row[0] == str(userId)) and (row[1] is None) and (row[2] is None) and self.check_new_password(username, password):
                    conn.execute('UPDATE users set password=' + "'" + str(password) + "'" + ' where userId=' + str(userId))
                    conn.execute('UPDATE users set username=' + "'" + str(username) + "'" + ' where userId=' + str(userId))
                    print('UPDATE users set username=' + "'" + str(username) + "'" + ' where userId=' + str(userId))
                    print("okay")
                    conn.commit()
                    conn.close()
                    return True
        except:
            return False

    def check_new_password(self, username, password):
        if len(password) < 8:
            return False
        if password.islower() or password.isalpha() or password.isupper() or password.isdigit():
            return False
        if username.isdigit():
            return False
        return True

    def list_connected(self):
        try:
            list=[]
            conn = sqlite3.connect('test4.db')
            str1 = "select*from users"
            print(str1)
            cursor = conn.execute(str1)
            for row in cursor:
                if (row[3] =='1'):
                    list.append(str(row[1]))
            return list
        except:
            return False
            print("user not found")


