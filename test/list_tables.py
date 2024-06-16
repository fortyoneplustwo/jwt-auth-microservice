import psycopg2
from dotenv import load_dotenv
import os 

# Load environment variables
load_dotenv()

dbname = os.getenv('DB_NAME')
dbuser = os.getenv('DB_USER')
dbpw = os.getenv('DB_PW')
host = os.getenv('HOST')
port = os.getenv('PORT')


# Connect to postgres database
conn = psycopg2.connect(f"dbname={dbname} user={dbuser} password={dbpw} host={host} port={port}")
cur = conn.cursor()

cur.execute("SELECT * FROM users")
results = cur.fetchall()
print(f"Users:\n{results}\n")

cur.execute("SELECT * FROM projects")
results = cur.fetchall()
print(f"Projects:\n{results}\n")

cur.execute("SELECT * FROM revoked")
results = cur.fetchall()
print(f"Revoked:\n{results}\n")
