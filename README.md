This repository showcases three backend projects developed for CSE380 (Spring 2025), focusing on secure authentication systems, database-driven applications, and microservices with Dockerized deployment. These projects demonstrate industry-relevant skills in backend development, security, and distributed systems.


# CSE380 Spring 2025 Projects

This repository contains three backend projects developed for CSE380 (Spring 2025).  
All projects are implemented using **Flask** and **SQLite3**, following strict security and parameterized-query requirements.


## Tech Stack
- Programming Language: Python (3.11+)
- Web Framework: Flask (3.x)
- Databases: SQLite3 (with parameterized queries to prevent SQL injection)
- Authentication & Security:
- SHA256 hashing with salts (hashlib)
- JSON Web Tokens (JWT) implemented from scratch with HMAC (hmac, base64)
- Inter-service Communication (Project 3): Python requests module for HTTP-based microservices communication
- Containerization: Docker (5 containers orchestrated via docker compose)



## Projects

### 1. Project 1 – User Management and Authentication
A secure user management system implementing:
- User creation with salted SHA256 password hashing
- JWT-based authentication (implemented from scratch using HMAC)
- Secure password updates with history checks
- User data viewing with JWT authorization

### 2. Project 2 – Movie Rating Site
A movie rating backend with:
- User roles (moderators & regular users)
- Movie creation, reviewing, and searching
- Normalized database design with genre support
- JWTs passed via Authorization header

### 3. Project 3 – Micro Foods Market
A microservices-based grocery store backend:
- 5 microservices (users, products, orders, search, logs)
- Each microservice runs in its own Docker container
- JWT validation across services, inter-service HTTP communication
- Full Docker Compose orchestration
