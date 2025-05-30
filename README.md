# FastAPI Beyond CRUD 

This is the source code for the [FastAPI Beyond CRUD](https://youtube.com/playlist?list=PLEt8Tae2spYnHy378vMlPH--87cfeh33P&si=rl-08ktaRjcm2aIQ) course. The course focuses on FastAPI development concepts that go beyond the basic CRUD operations.

For more details, visit the project's [website](https://jod35.github.io/fastapi-beyond-crud-docs/site/).

## Table of Contents

1. [Getting Started](#getting-started)
2. [Prerequisites](#prerequisites)
3. [Project Setup](#project-setup)
4. [Running the Application](#running-the-application)
5. [Running Tests](#running-tests)
6. [Contributing](#contributing)

## Getting Started
Follow the instructions below to set up and run your FastAPI project.

### Prerequisites
Ensure you have the following installed:

- Python >= 3.10
- PostgreSQL
- Redis

### Project Setup
1. Clone the project repository:
    ```bash
    git clone https://github.com/jod35/fastapi-beyond-CRUD.git
    ```
   
2. Navigate to the project directory:
    ```bash
    cd fastapi-beyond-CRUD/
    ```

3. Create and activate a virtual environment:
    ```bash
    python3 -m venv env
    source env/bin/activate
    ```

4. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

5. Set up environment variables by copying the example configuration:
    ```bash
    cp .env.example .env
    ```

6. Run database migrations to initialize the database schema:
    ```bash
    alembic upgrade head
    ```

7. Open a new terminal and ensure your virtual environment is active. Start the Celery worker (Linux/Unix shell):
    ```bash
    sh runworker.sh
    ```

## Running the Application
Start the application:

```bash
fastapi dev src/
```
Alternatively, you can run the application using Docker:
```bash
docker compose up -d
```
## Running Tests
Run the tests using this command
```bash
pytest
```

## Contributing
I welcome contributions to improve the documentation! You can contribute [here](https://github.com/jod35/fastapi-beyond-crud-docs).

```
TIMESTAMPS
00:00:00 - Introduction  
00:01:00 - Project setup  
00:07:30 - Build a simple web server  
00:10:45 - Run the server with FastAPI CLI  
00:14:11 - Path parameters  
00:17:23 - Choosing an HTTP client  
00:20:58 - Query parameters  
00:24:40 - Using Path and Query parameters  
00:26:51 - Optional Query parameters  
00:31:48 - Request Body  
00:39:11 - Reading and setting headers  
00:49:43 - Build a REST API on a Python List  
01:23:37 - Organizing API Paths with Routers  
01:38:22 - Databases With SQLModel  
01:42:33 - Setting up a database  
01:44:13 - Settings management with Pydantic settings  
01:53:38 - Async SQLModel setup  
01:58:38 - Database connection with lifespan events  
02:10:02 - Creating a database model with SQLModel  
02:20:00 - Creating database tables  
02:27:08 - CRUD With SQLModel  
02:29:48 - Separate CRUD logic using service classes  
02:55:53 - Intro to Dependency Injection  
03:01:20 - Use service methods in API path handlers  
03:33:35 - Create the user auth model  
03:42:09 - Database Migrations With Alembic  
03:59:57 - User Account Creation  
04:18:55 - Password hashing with passlib  
04:25:42 - User Account Creation endpoint  
04:42:57 - Intro to JWT Authentication  
04:48:29 - PyJWT Setup  
05:01:13 - User Login Endpoint  
05:13:59 - HTTP Bearer Authentication  
05:33:14 - Regaining Access with refresh tokens  
05:50:04 - Revoking Tokens using Redis  
06:07:39 - Role-Based Access Control  
06:09:45 - Get the currently authenticated user  
06:20:25 - Adding roles to the user model  
06:26:55 - Creating the Role Checker dependency  
06:39:24 - Handling Model and Schema Relationships  
07:05:53 - More Model and Schema Relationships  
07:59:58 - Error Handling  
08:04:06 - Create custom API Exceptions  
08:18:14 - Creating exception handlers for those exceptions  
08:23:26 - Register Error handlers on the app  
08:33:25 - Intro to Middleware  
08:36:54 - Creating a custom logging middleware  
08:53:28 - Another middleware example  
08:59:36 - Using Custom ASGI middleware with FastAPI  
09:00:21 - Adding CORS Middleware  
09:03:34 - Adding Trusted Hosts  
09:05:04 - Adding Email support  
09:06:39 - Setting Up FastAPI-Mail  
09:21:46 - Sending your first email  
09:31:21 - User account verification  
10:07:51 - Password Resets  
10:40:38 - Background Tasks  
10:43:00 - FastAPI Background Tasks  
10:45:44 - Background Tasks with Celery and Redis  
11:16:17 - Celery Monitoring With Flower  
11:23:48 - API Documentation with SwaggerUI and Redoc  
11:36:02 - API Testing  
11:37:10 - Unit testing with Unittest Mock and Pytest  
12:01:27 - Document-driven Testing with Schemathesis  
12:09:17 - Deployment on Render.com
```