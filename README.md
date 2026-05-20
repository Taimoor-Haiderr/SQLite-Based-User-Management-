# SQLite-Based-User-Management-
Python GUI user management system with SQLite, secure authentication (hashed passwords), full CRUD, admin panel, login lockout, forgot-password reset, RBAC, and CSV export — built with Tkinter.


A professional Python desktop application for managing users with a SQLite backend and a light-themed Tkinter GUI. It demonstrates real-world patterns used in backend user systems: secure authentication, role-based access, and full CRUD operations.


## Features

### Core
- User registration and secure login
- Password hashing with `hashlib` (SHA-256)
- Session-based logged-in user tracking
- Full CRUD: create, read, update, delete users
- SQLite storage with parameterized queries (SQL injection safe)

### Security
- Passwords never stored in plain text
- Login attempt limit with temporary account lockout
- Forgot password flow with reset tokens
- Role-based access control (Admin / User)

### Admin Panel
- View all users in a sortable table
- Search by username or email
- Filter users by role
- Delete any user (except self from admin view)
- Export filtered users to CSV

### User Experience
- Clean, light-themed professional GUI
- Input validation and error handling
- Modular code: database layer separated from UI

## Tech Stack

| Component      | Technology        |
|----------------|-------------------|
| Language       | Python 3.8+       |
| Database       | SQLite (`sqlite3`)|
| GUI            | Tkinter / ttk     |
| Security       | `hashlib`, `secrets` |

## Requirements

- Python 3.8 or higher
- No external packages (stdlib only)
