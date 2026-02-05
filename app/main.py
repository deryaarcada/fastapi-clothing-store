from itertools import product
from fastapi import FastAPI, HTTPException
import os, psycopg
from psycopg.rows import dict_row


from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, status


DATABASE_URL = os.getenv("DATABASE_URL")

app = FastAPI()

def get_conn():
    return psycopg.connect(DATABASE_URL, autocommit=True, row_factory=psycopg.rows.dict_row)


from datetime import datetime, timedelta, timezone 
# Cryptagraphy and JWT settings
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

# JWT Settings 
SECRET_KEY = "gercek-uygulamada-buraya-rastgele-uzun-bir-string-gelir" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        # Decode JWT Token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role")
        if user_id is None:
            raise HTTPException(status_code=401, detail="The token is invalid or has expired.")
        return {"user_id": user_id, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="The session has expired. Please log in again.")



@app.get("/")
def get_root():
    return { "msg": "Clothing Store v0.1" }

# GET /categories 
@app.get("/categories")
def get_categories():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT category_id, name FROM categories ORDER BY category_id;")
        return cur.fetchall()
    
# GET /products
@app.get("/products")
def get_products():
    with get_conn() as conn, conn.cursor() as cur:
        # Join categories to show product name, category name, price, and stock
        cur.execute("""
            SELECT p.name, c.name as category_name, p.price, p.stock 
            FROM products p 
            INNER JOIN categories c ON p.category_id = c.category_id;
        """)
        return cur.fetchall()
    
# GET /orders - List your own orders
@app.get("/orders")
def get_my_orders(current_user: dict = Depends(get_current_user)):
    # Get user_id from the token
    user_id = current_user["user_id"] 
    
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT 
                o.order_id, 
                o.order_date, 
                p.name as product_name, 
                oi.quantity, 
                (oi.quantity * p.price) as total_price
            FROM orders o
            JOIN order_items oi ON o.order_id = oi.order_id
            JOIN products p ON oi.product_id = p.product_id
            WHERE o.customer_id = %s
            ORDER BY o.order_date DESC;
        """, (user_id,))
        orders = cur.fetchall()
        return orders
   

@app.post("/orders", status_code=201)
def create_order(data: dict):
    customer_id = data.get("customer_id")
    product_id = data.get("product_id")
    quantity = data.get("quantity")

    if not all([customer_id, product_id, quantity]):
        raise HTTPException(status_code=400, detail="There are missing fields.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. Product availability check
            cur.execute("SELECT name, price, stock FROM products WHERE product_id = %s FOR UPDATE;", (product_id,))
            product_data = cur.fetchone()

            if not product_data:
                raise HTTPException(status_code=404, detail="The product is not found.")
            
            if product_data["stock"] < quantity:
                raise HTTPException(status_code=400, detail="The requested quantity is not available in stock.")

            # 2.Create order (Orders table)
            cur.execute("""
                INSERT INTO orders (customer_id) 
                VALUES (%s) 
                RETURNING order_id;
            """, (customer_id,))
            order_data = cur.fetchone() 
            order_id = order_data["order_id"]

            # 3. Add order item (Order_Items table)
            cur.execute("""
                INSERT INTO order_items (order_id, product_id, quantity) 
                VALUES (%s, %s, %s)
                RETURNING order_item_id, quantity;
            """, (order_id, product_id, quantity))
            item_info = cur.fetchone()

            # 4. Stock update
            cur.execute("""
                UPDATE products 
                SET stock = stock - %s 
                WHERE product_id = %s 
                RETURNING stock;
                """, (quantity, product_id))

            updated_stock = cur.fetchone()
            print(f"New stock quantity: {updated_stock['stock']}") 
            # If it is not autocommit push the changes:
            conn.commit() 
            # 5. Prepare response
            return {
                "order_id": order_id,
                "product_name": product_data["name"],
                "quantity": item_info["quantity"],
                "total_price": float(product_data["price"] * quantity),
                "status": "success"
            }




# GET /statistics/products
@app.get("/statistics/products")
def get_product_statistics():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT 
                p.name, 
                SUM(COALESCE(oi.quantity, 0)) as total_sold_quantity, 
                COUNT(oi.order_item_id) as transaction_count,
                SUM(COALESCE(oi.quantity * p.price, 0)) as turnover 
            FROM products p
            LEFT JOIN order_items oi ON p.product_id = oi.product_id
            GROUP BY p.product_id, p.name
            ORDER BY turnover DESC;
        """)
        return cur.fetchall()



# --- Functions for password hashing and JWT token creation

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def hash_password(password: str):
    """ Hashing password with bcrypt limit (72)"""
    if not password:
        return None
    # Limit the password to 72 bytes for bcrypt (Value error prevention)
    return pwd_context.hash(password[:72])

def verify_password(plain_password, hashed_password):
    """Verify password in the database"""
    if not hashed_password or not plain_password:
        return False
    try:
        # .strip() delete hidden characters like new line
        # [:72] take guarantee for bcrypt limit
        return pwd_context.verify(plain_password[:72], hashed_password.strip())
    except Exception as e:
        print(f"Verification error: {e}")
        return False

# --- ENDPOINTS---
# create user (register)
@app.post("/users", status_code=201)
def register_user(data: dict):
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    password = data.get("password")

    if not all([first_name, last_name, email, password]):
        raise HTTPException(status_code=400, detail="All fields are required.")

    # Check password before hash 
    password_hash = hash_password(password)

    with get_conn() as conn, conn.cursor() as cur:
        try:
            cur.execute("""
                INSERT INTO customers (first_name, last_name, email, password_hash, role)
                VALUES (%s, %s, %s, %s, 'customer')
                RETURNING customer_id, email, role;
            """, (first_name, last_name, email, password_hash))
            return cur.fetchone()
        except Exception as e:
            # If email already exists, a unique constraint violation will occur
            raise HTTPException(status_code=400, detail="This email is already registered.")

#login endpoint
@app.post("/users/login")
def login(data: dict):
    email = data.get("email")
    password = data.get("password")

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT customer_id, email, password_hash, role FROM customers WHERE email = %s", (email,))
        user = cur.fetchone()

        # Check user existence and password
        if not user or not verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Wrong email or password.")

        # Create JWT Token
        access_token = create_access_token(
            data={"sub": str(user["customer_id"]), "role": user["role"]}
        )
        return {"access_token": access_token, "token_type": "bearer"}
    

@app.get("/statistics/customers")
def get_customer_statistics(current_user: dict = Depends(get_current_user)):
    # 1. 403 error raise if the user is not admin
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Just admins can access this resource."
        )

    # 2. run sql if it is admin
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT 
                c.customer_id, 
                c.first_name || ' ' || c.last_name as customer_name,
                COUNT(DISTINCT o.order_id) as order_count, 
                SUM(oi.quantity * p.price) as total_spent 
            FROM customers c
            LEFT JOIN orders o ON c.customer_id = o.customer_id
            LEFT JOIN order_items oi ON o.order_id = oi.order_id
            LEFT JOIN products p ON oi.product_id = p.product_id
            GROUP BY c.customer_id, c.first_name, c.last_name;
        """)
        return cur.fetchall()

# DELETE /users/{customer_id}
@app.delete("/users/{customer_id}")
def delete_user(customer_id: int, current_user: dict = Depends(get_current_user)):
    # 1. Check if current user is admin
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Just admins can delete users.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 2. Check if user exists
            cur.execute("SELECT first_name FROM customers WHERE customer_id = %s", (customer_id,))
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found.")

            # 3. Delete the user from database (cascade delete will handle related records otherwise delete orders as well)
            cur.execute("DELETE FROM customers WHERE customer_id = %s", (customer_id,))
            
            return {"msg": f"The user {customer_id} ({user['first_name']}) is deleted successfully."}


# Add product (POST)
@app.post("/products")
def add_product(data: dict, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="It needs admin privileges.")
    
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("""
            INSERT INTO products (category_id, name, price, stock)
            VALUES (%s, %s, %s, %s) RETURNING product_id;
        """, (data['category_id'], data['name'], data['price'], data['stock']))
        return cur.fetchone()

# Delete product (DELETE)
@app.delete("/products/{product_id}")
def delete_product(product_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="It needs admin privileges.")
    
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM products WHERE product_id = %s", (product_id,))
        return {"msg": "Product deleted successfully"}


# PATCH /products/{id} - It only updates the fields that have been sent with the product.
@app.patch("/products/{product_id}")
def update_product(product_id: int, data: dict, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges are required.")

    with get_conn() as conn, conn.cursor() as cur:
        # Dynamically update whichever fields are received.
        for key, value in data.items():
            # !!Be cautious about the risk of SQL Injection, simply put:!!
            cur.execute(f"UPDATE products SET {key} = %s WHERE product_id = %s", (value, product_id))
        
        return {"msg": "Product updated successfully"}
    

# PUT /products/{product_id} - It updates all fields of the product.
@app.put("/products/{product_id}")
def update_product_full(product_id: int, data: dict, current_user: dict = Depends(get_current_user)):
    # 1. Check admin role
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Only admins can update products."
        )

    # 2. Get all fields from the request body (PUT asks for all fields)
    name = data.get("name")
    price = data.get("price")
    stock = data.get("stock")
    category_id = data.get("category_id")

    if not all([name, price, stock, category_id]):
        raise HTTPException(status_code=400, detail="All fields (name, price, stock, category_id) are required for PUT.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 3. Ürünün var olup olmadığını kontrol et
            cur.execute("SELECT product_id FROM products WHERE product_id = %s", (product_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Product not found.")

            # 4. Tüm tabloyu güncelle
            cur.execute("""
                UPDATE products 
                SET name = %s, price = %s, stock = %s, category_id = %s
                WHERE product_id = %s
                RETURNING product_id, name, price, stock;
            """, (name, price, stock, category_id, product_id))
            
            updated_product = cur.fetchone()
            conn.commit()
            
            return {"msg": "Product updated successfully", "product": updated_product}
