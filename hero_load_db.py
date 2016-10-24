import csv
import MySmysql;QLdb

mydb = MySQLdb.connect(host='localhost',
    user='root',
    passwd='',
    db='mydb')
cursor = mydb.cursor()

csv_data = csv.reader(file('/tmp/heroaccount.csv'))
for row in csv_data:

    cursor.execute('INSERT INTO heroneutrinoaccounts(domain, \
          herousername, \
          heropassword, \
          used )' \
          'VALUES("%s", "%s", "%s",%s)',
          row)
#close the connection to the database.
mydb.commit()
cursor.close()
print "Done"