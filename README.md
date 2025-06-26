# Tarpaulin Course Management Tool

Tarpaulin is a lightweight, RESTful course management API designed as a simple alternative to platforms like Canvas. Built with Python 3 and deployed on Google Cloud Platform using App Engine and Datastore, Tarpaulin offers a role-based system for managing users, courses, and enrollments.

## Features

- **Full RESTful API** with 13 endpoints
- **Role-based access control** with `admin`, `instructor`, and `student` roles
- **JWT Authentication** via [Auth0](https://auth0.com)
- **Avatar support** with image uploads stored in Google Cloud Storage
- **Course and enrollment management**
- **Pagination** for course listings

## Tech Stack

- **Python 3**
- **Google App Engine** (deployment)
- **Google Cloud Datastore** (database)
- **Google Cloud Storage** (file storage)
- **Auth0** (authentication)

## API Overview

| Functionality              | Endpoint                          | Protected           | Description                          |
|---------------------------|-----------------------------------|---------------------|--------------------------------------|
| User Login                | `POST /users/login`               | Yes (Auth0 users)   | Auth0 issues JWTs                    |
| Get All Users             | `GET /users`                      | Admin only          | Basic info for all users             |
| Get a User                | `GET /users/:id`                  | Admin or Self       | Full profile and courses             |
| Upload Avatar             | `POST /users/:id/avatar`          | Self only           | Upload image to GCS                  |
| Get Avatar                | `GET /users/:id/avatar`           | Self only           | Fetch avatar from GCS                |
| Delete Avatar             | `DELETE /users/:id/avatar`        | Self only           | Remove avatar                        |
| Create Course             | `POST /courses`                   | Admin only          | Add a new course                     |
| Get All Courses           | `GET /courses`                    | Public              | Paginated course list                |
| Get Course Details        | `GET /courses/:id`                | Public              | Single course info                   |
| Update Course             | `PATCH /courses/:id`              | Admin only          | Partial update                       |
| Delete Course             | `DELETE /courses/:id`             | Admin only          | Remove course and enrollments        |
| Manage Enrollment         | `PATCH /courses/:id/students`     | Admin or Instructor | Enroll/disenroll students            |
| View Enrollment           | `GET /courses/:id/students`       | Admin or Instructor | List enrolled students               |

## Authentication & Roles

- **Auth0 JWTs** are used for authentication.
- Roles (`admin`, `instructor`, `student`) are stored in Datastore and determine API access levels.

## Users (for demo/testing)

Nine demo users are pre-configured in Auth0:

- **1 Admin** – `admin1@osu.com`
- **2 Instructors** – `instructor1@osu.com`, `instructor2@osu.com`
- **6 Students** – `student1@osu.com` through `student6@osu.com`

All users share the same password for testing purposes.

## Deployment

- Hosted on **Google App Engine**
- Uses **Google Cloud Datastore** for structured data
- Avatar files stored in **Google Cloud Storage**
