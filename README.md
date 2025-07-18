# CSE380-CloudInfraBackend-Projects
Three backend projects for CSE380 (Spring 2025) built with Flask and SQLite3, covering user authentication, a movie rating system, and a Dockerized microservices grocery store application.


# CSE380 Spring 2025 Projects

This repository contains three backend projects developed for CSE380 (Spring 2025).  
All projects are implemented using **Flask** and **SQLite3**, following strict security and parameterized-query requirements.

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
