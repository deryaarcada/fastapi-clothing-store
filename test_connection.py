import psycopg
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
print(f"Conn string: {DATABASE_URL}")

try:
    conn = psycopg.connect(DATABASE_URL)
    print("✓ Connection successful!")
    
    # Test sorgusu
    with conn.cursor() as cur:
        cur.execute("SELECT 1 as test")
        result = cur.fetchone()
        print(f"✓ TEst query worked: {result}")
    
    conn.close()
except Exception as e:
    print(f"XXX Connection error: {e}")
