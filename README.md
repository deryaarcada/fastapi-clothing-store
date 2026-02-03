# FastAPI Clothing Store API
A secure, containerized FastAPI backend application for a clothing store, running on Docker. This project features JWT-based authentication, password hashing, automated inventory management, and advanced sales statistics.
## Features
Product & Category Management: Complete CRUD operations for products and categories.</br>
Authentication System: Secure user registration with bcrypt password hashing.</br>
JWT Authorization: Secure token-based access control.</br>
Role-Based Access Control (RBAC):</br>
- Customers: Log in, place orders, and view their own order history.</br>
- Admins: Manage products (POST, PUT, DELETE), delete users, and access sales statistics.</br>
Inventory Integrity: Automatic and atomic (transaction-safe) stock reduction upon ordering.</br>
## Tech Stack
Framework: FastAPI </br>
Database: PostgreSQL</br>
Database Driver: Psycopg 3</br>
Security: JWT (python-jose), Bcrypt (passlib)</br>
DevOps: Docker & Docker-Compose</br>

## Installation & Setup
1. Clone the Repository:</br>
bash =></br>
 - git clone <your-repository-url></br>
 - cd fastapi-clothing-store</br>
2. Run with Docker:</br>
bash =></br>
- docker-compose up --build</br>
The API will be available at http://localhost:8080. </br>

## Admin Setup
To set your initial user as an admin, run the following SQL command in your database: </br>
sql =></br>
- UPDATE customers SET role = 'admin' WHERE email = 'your-email@example.com';</br>