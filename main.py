from __future__ import annotations
import csv
import hashlib
import re
import secrets
import sqlite3
import tkinter as tk
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional, Tuple

# =============================================================================
# CONFIGURATION
# =============================================================================
DB_NAME = "users.db"
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
PASSWORD_MIN_LEN = 6
ROLES = ("User", "Admin")

COLORS = {
    "bg": "#f4f6f9",
    "card": "#ffffff",
    "primary": "#2563eb",
    "text": "#1e293b",
    "muted": "#64748b",
    "border": "#e2e8f0",
}


# =============================================================================
# UTILITIES
# =============================================================================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def validate_email(email: str) -> bool:
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return bool(re.match(pattern, email.strip()))


def validate_username(username: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_]{3,30}$", username.strip()))


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =============================================================================
# DATABASE LAYER
# =============================================================================
class Database:
    def __init__(self, db_path: str = DB_NAME) -> None:
        self.db_path = db_path
        self._init_database()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        phone TEXT DEFAULT '',
                        role TEXT NOT NULL DEFAULT 'User',
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS login_attempts (
                        username TEXT PRIMARY KEY,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        locked_until TEXT
                    );

                    CREATE TABLE IF NOT EXISTS reset_tokens (
                        username TEXT PRIMARY KEY,
                        token TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    """
                )
                admin = conn.execute(
                    "SELECT id FROM users WHERE username = ?", ("admin",)
                ).fetchone()
                if admin is None:
                    conn.execute(
                        """
                        INSERT INTO users
                        (username, email, password, phone, role, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "admin",
                            "admin@system.local",
                            hash_password("Admin@123"),
                            "",
                            "Admin",
                            now_str(),
                        ),
                    )
        except sqlite3.Error as exc:
            raise RuntimeError(f"Database init failed: {exc}") from exc

    @staticmethod
    def verify_password(plain: str, hashed: str) -> bool:
        return hash_password(plain) == hashed

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        phone: str,
        role: str = "User",
    ) -> Tuple[bool, str]:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO users
                    (username, email, password, phone, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        username.strip(),
                        email.strip().lower(),
                        hash_password(password),
                        phone.strip(),
                        role if role in ROLES else "User",
                        now_str(),
                    ),
                )
            return True, "User registered successfully."
        except sqlite3.IntegrityError:
            return False, "Username or email already exists."
        except sqlite3.Error as exc:
            return False, f"Registration failed: {exc}"

    def get_user_by_username(self, username: str) -> Optional[sqlite3.Row]:
        try:
            with self._connect() as conn:
                return conn.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username.strip(),),
                ).fetchone()
        except sqlite3.Error:
            return None

    def get_user_by_id(self, user_id: int) -> Optional[sqlite3.Row]:
        try:
            with self._connect() as conn:
                return conn.execute(
                    "SELECT * FROM users WHERE id = ?", (user_id,)
                ).fetchone()
        except sqlite3.Error:
            return None

    def update_user(
        self,
        user_id: int,
        email: str,
        phone: str,
        role: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Tuple[bool, str]:
        try:
            with self._connect() as conn:
                if password:
                    conn.execute(
                        """
                        UPDATE users
                        SET email = ?, phone = ?,
                            role = COALESCE(?, role),
                            password = ?
                        WHERE id = ?
                        """,
                        (
                            email.strip().lower(),
                            phone.strip(),
                            role,
                            hash_password(password),
                            user_id,
                        ),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE users
                        SET email = ?, phone = ?,
                            role = COALESCE(?, role)
                        WHERE id = ?
                        """,
                        (email.strip().lower(), phone.strip(), role, user_id),
                    )
            return True, "Profile updated successfully."
        except sqlite3.IntegrityError:
            return False, "Email already in use."
        except sqlite3.Error as exc:
            return False, f"Update failed: {exc}"

    def delete_user(self, user_id: int) -> Tuple[bool, str]:
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM users WHERE id = ?", (user_id,)
                )
                if cursor.rowcount == 0:
                    return False, "User not found."
            return True, "Account deleted successfully."
        except sqlite3.Error as exc:
            return False, f"Delete failed: {exc}"

    def get_all_users(
        self,
        role_filter: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[sqlite3.Row]:
        query = "SELECT * FROM users WHERE 1=1"
        params: List = []
        if role_filter and role_filter != "All":
            query += " AND role = ?"
            params.append(role_filter)
        if search and search.strip():
            query += " AND (username LIKE ? OR email LIKE ?)"
            like = f"%{search.strip()}%"
            params.extend([like, like])
        query += " ORDER BY id ASC"
        try:
            with self._connect() as conn:
                return conn.execute(query, params).fetchall()
        except sqlite3.Error:
            return []

    def get_login_attempts(self, username: str) -> Optional[sqlite3.Row]:
        try:
            with self._connect() as conn:
                return conn.execute(
                    "SELECT * FROM login_attempts WHERE username = ?",
                    (username.strip(),),
                ).fetchone()
        except sqlite3.Error:
            return None

    def record_failed_login(self, username: str) -> None:
        username = username.strip()
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT attempts FROM login_attempts WHERE username = ?",
                    (username,),
                ).fetchone()
                attempts = (row["attempts"] + 1) if row else 1
                locked_until = None
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    locked_until = (
                        datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    """
                    INSERT INTO login_attempts (username, attempts, locked_until)
                    VALUES (?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        attempts = excluded.attempts,
                        locked_until = excluded.locked_until
                    """,
                    (username, attempts, locked_until),
                )
        except sqlite3.Error:
            pass

    def clear_login_attempts(self, username: str) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM login_attempts WHERE username = ?",
                    (username.strip(),),
                )
        except sqlite3.Error:
            pass

    def is_locked(self, username: str) -> Tuple[bool, str]:
        row = self.get_login_attempts(username)
        if not row or not row["locked_until"]:
            return False, ""
        try:
            locked_until = datetime.strptime(
                row["locked_until"], "%Y-%m-%d %H:%M:%S"
            )
            if datetime.now() < locked_until:
                minutes_left = int(
                    (locked_until - datetime.now()).total_seconds() // 60
                ) + 1
                return True, (
                    f"Account locked. Try again in ~{minutes_left} minute(s)."
                )
            self.clear_login_attempts(username)
        except ValueError:
            self.clear_login_attempts(username)
        return False, ""

    def create_reset_token(self, username: str) -> Tuple[bool, str, str]:
        user = self.get_user_by_username(username)
        if user is None:
            return False, "Username not found.", ""
        token = secrets.token_hex(4).upper()
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO reset_tokens (username, token, created_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        token = excluded.token,
                        created_at = excluded.created_at
                    """,
                    (username.strip(), token, now_str()),
                )
            return True, "Reset token generated.", token
        except sqlite3.Error as exc:
            return False, str(exc), ""

    def reset_password_with_token(
        self,
        username: str,
        token: str,
        new_password: str,
    ) -> Tuple[bool, str]:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT token FROM reset_tokens WHERE username = ?",
                    (username.strip(),),
                ).fetchone()
                if row is None or row["token"] != token.strip().upper():
                    return False, "Invalid or expired token."
                conn.execute(
                    "UPDATE users SET password = ? WHERE username = ?",
                    (hash_password(new_password), username.strip()),
                )
                conn.execute(
                    "DELETE FROM reset_tokens WHERE username = ?",
                    (username.strip(),),
                )
            self.clear_login_attempts(username)
            return True, "Password reset successful."
        except sqlite3.Error as exc:
            return False, f"Reset failed: {exc}"

    def export_users_csv(
        self,
        filepath: str,
        role_filter: Optional[str] = None,
        search: Optional[str] = None,
    ) -> None:
        users = self.get_all_users(role_filter, search)
        with open(filepath, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(
                ["ID", "Username", "Email", "Phone", "Role", "Created At"]
            )
            for user in users:
                writer.writerow(
                    [
                        user["id"],
                        user["username"],
                        user["email"],
                        user["phone"],
                        user["role"],
                        user["created_at"],
                    ]
                )


# =============================================================================
# SESSION
# =============================================================================
class Session:
    def __init__(self) -> None:
        self._user: Optional[dict] = None

    def login(self, user_row: sqlite3.Row) -> None:
        self._user = dict(user_row) if user_row else None

    def logout(self) -> None:
        self._user = None

    @property
    def user(self) -> Optional[dict]:
        return self._user

    @property
    def is_logged_in(self) -> bool:
        return self._user is not None

    @property
    def is_admin(self) -> bool:
        return self.is_logged_in and self._user.get("role") == "Admin"

    @property
    def user_id(self) -> Optional[int]:
        return self._user["id"] if self._user else None


# =============================================================================
# GUI APPLICATION
# =============================================================================
class UserManagementApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.db = Database()
        self.session = Session()
        self._configure_window()
        self._configure_styles()
        self.show_login_screen()

    def _configure_window(self) -> None:
        self.root.title("User Management System")
        self.root.geometry("960x640")
        self.root.minsize(800, 560)
        self.root.configure(bg=COLORS["bg"])

    def _configure_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("Card.TFrame", background=COLORS["card"])
        style.configure(
            "Title.TLabel",
            background=COLORS["card"],
            foreground=COLORS["text"],
            font=("Segoe UI", 18, "bold"),
        )
        style.configure(
            "Subtitle.TLabel",
            background=COLORS["card"],
            foreground=COLORS["muted"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "TLabel",
            background=COLORS["card"],
            foreground=COLORS["text"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Header.TLabel",
            background=COLORS["bg"],
            foreground=COLORS["text"],
            font=("Segoe UI", 14, "bold"),
        )
        style.configure("TButton", font=("Segoe UI", 10), padding=8)

    def _clear_window(self) -> None:
        for widget in self.root.winfo_children():
            widget.destroy()

    def _create_card(self, title: str, subtitle: str = "") -> ttk.Frame:
        outer = ttk.Frame(self.root, style="TFrame")
        outer.pack(fill=tk.BOTH, expand=True, padx=40, pady=30)

        card = tk.Frame(
            outer,
            bg=COLORS["card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        card.pack(expand=True)

        inner = ttk.Frame(card, style="Card.TFrame", padding=32)
        inner.pack(fill=tk.BOTH, expand=True)

        ttk.Label(inner, text=title, style="Title.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(inner, text=subtitle, style="Subtitle.TLabel").pack(
                anchor="w", pady=(4, 20)
            )
        return inner

    def _add_labeled_entry(
        self,
        parent: ttk.Frame,
        label: str,
        variable: tk.StringVar,
        show: Optional[str] = None,
    ) -> None:
        row = ttk.Frame(parent, style="Card.TFrame")
        row.pack(fill=tk.X, pady=6)
        ttk.Label(row, text=label).pack(anchor="w")
        options = {"textvariable": variable, "width": 42}
        if show:
            options["show"] = show
        ttk.Entry(row, **options).pack(anchor="w", pady=4)

    # -------------------------------------------------------------------------
    # Screens
    # -------------------------------------------------------------------------
    def show_login_screen(self) -> None:
        self._clear_window()
        frame = self._create_card("Welcome Back", "Sign in to your account")

        self.login_username = tk.StringVar()
        self.login_password = tk.StringVar()

        self._add_labeled_entry(frame, "Username", self.login_username)
        self._add_labeled_entry(
            frame, "Password", self.login_password, show="*"
        )

        buttons = ttk.Frame(frame, style="Card.TFrame")
        buttons.pack(fill=tk.X, pady=(16, 8))

        ttk.Button(buttons, text="Login", command=self._handle_login).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(
            buttons, text="Register", command=self.show_register_screen
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            buttons, text="Forgot Password", command=self.show_forgot_screen
        ).pack(side=tk.LEFT, padx=4)

        ttk.Label(
            frame,
            text="Default admin: admin / Admin@123",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(12, 0))

        self.root.bind("<Return>", lambda _event: self._handle_login())

    def show_register_screen(self) -> None:
        self._clear_window()
        frame = self._create_card("Create Account", "Register a new user")

        self.reg_username = tk.StringVar()
        self.reg_email = tk.StringVar()
        self.reg_password = tk.StringVar()
        self.reg_phone = tk.StringVar()
        self.reg_role = tk.StringVar(value="User")

        self._add_labeled_entry(frame, "Username", self.reg_username)
        self._add_labeled_entry(frame, "Email", self.reg_email)
        self._add_labeled_entry(
            frame, "Password", self.reg_password, show="*"
        )
        self._add_labeled_entry(frame, "Phone", self.reg_phone)

        role_row = ttk.Frame(frame, style="Card.TFrame")
        role_row.pack(fill=tk.X, pady=6)
        ttk.Label(role_row, text="Role").pack(anchor="w")
        ttk.Combobox(
            role_row,
            textvariable=self.reg_role,
            values=ROLES,
            state="readonly",
            width=20,
        ).pack(anchor="w", pady=4)

        buttons = ttk.Frame(frame, style="Card.TFrame")
        buttons.pack(fill=tk.X, pady=(16, 0))
        ttk.Button(
            buttons, text="Register", command=self._handle_register
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            buttons, text="Back to Login", command=self.show_login_screen
        ).pack(side=tk.LEFT)

    def show_forgot_screen(self) -> None:
        self._clear_window()
        frame = self._create_card(
            "Forgot Password",
            "Generate a token, then reset your password",
        )

        self.forgot_username = tk.StringVar()
        self.forgot_token = tk.StringVar()
        self.forgot_new_password = tk.StringVar()
        self.forgot_token_label = tk.StringVar(value="")

        self._add_labeled_entry(frame, "Username", self.forgot_username)
        ttk.Button(
            frame, text="Generate Token", command=self._handle_generate_token
        ).pack(anchor="w", pady=8)
        ttk.Label(
            frame, textvariable=self.forgot_token_label, style="Subtitle.TLabel"
        ).pack(anchor="w", pady=4)
        self._add_labeled_entry(frame, "Reset Token", self.forgot_token)
        self._add_labeled_entry(
            frame, "New Password", self.forgot_new_password, show="*"
        )

        buttons = ttk.Frame(frame, style="Card.TFrame")
        buttons.pack(fill=tk.X, pady=(16, 0))
        ttk.Button(
            buttons,
            text="Reset Password",
            command=self._handle_reset_password,
        ).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(
            buttons, text="Back to Login", command=self.show_login_screen
        ).pack(side=tk.LEFT)

    def show_dashboard(self) -> None:
        self._clear_window()

        header = ttk.Frame(self.root, style="TFrame", padding=(24, 20))
        header.pack(fill=tk.X)
        ttk.Label(
            header,
            text=(
                f"Dashboard — {self.session.user['username']} "
                f"({self.session.user['role']})"
            ),
            style="Header.TLabel",
        ).pack(side=tk.LEFT)
        ttk.Button(header, text="Logout", command=self._handle_logout).pack(
            side=tk.RIGHT
        )

        nav = ttk.Frame(self.root, style="TFrame", padding=(24, 0))
        nav.pack(fill=tk.X)

        ttk.Button(nav, text="View Profile", command=self._show_profile).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(
            nav, text="Update Profile", command=self._show_update_dialog
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            nav, text="Delete My Account", command=self._handle_delete_self
        ).pack(side=tk.LEFT, padx=4)

        if self.session.is_admin:
            ttk.Button(
                nav, text="Admin Panel", command=self._show_admin_panel
            ).pack(side=tk.LEFT, padx=4)

        body = ttk.Frame(self.root, style="TFrame", padding=24)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            body,
            text="Select an action from the menu above.",
            background=COLORS["bg"],
            foreground=COLORS["muted"],
            font=("Segoe UI", 11),
        ).pack(anchor="nw")

    def _show_profile(self) -> None:
        user = self.db.get_user_by_id(self.session.user_id)
        if user is None:
            messagebox.showerror("Error", "Could not load profile.")
            return
        messagebox.showinfo(
            "My Profile",
            (
                f"ID: {user['id']}\n"
                f"Username: {user['username']}\n"
                f"Email: {user['email']}\n"
                f"Phone: {user['phone'] or 'N/A'}\n"
                f"Role: {user['role']}\n"
                f"Created: {user['created_at']}"
            ),
        )

    def _show_update_dialog(self) -> None:
        user = self.db.get_user_by_id(self.session.user_id)
        if user is None:
            messagebox.showerror("Error", "User not found.")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Update Profile")
        dialog.geometry("420x400")
        dialog.configure(bg=COLORS["card"])
        dialog.transient(self.root)
        dialog.grab_set()

        email_var = tk.StringVar(value=user["email"])
        phone_var = tk.StringVar(value=user["phone"] or "")
        password_var = tk.StringVar()
        role_var = tk.StringVar(value=user["role"])

        pad = {"padx": 20, "pady": 8}
        ttk.Label(dialog, text="Email").pack(anchor="w", **pad)
        ttk.Entry(dialog, textvariable=email_var, width=40).pack(**pad)
        ttk.Label(dialog, text="Phone").pack(anchor="w", **pad)
        ttk.Entry(dialog, textvariable=phone_var, width=40).pack(**pad)
        ttk.Label(dialog, text="New Password (optional)").pack(anchor="w", **pad)
        ttk.Entry(
            dialog, textvariable=password_var, show="*", width=40
        ).pack(**pad)

        if self.session.is_admin:
            ttk.Label(dialog, text="Role").pack(anchor="w", **pad)
            ttk.Combobox(
                dialog,
                textvariable=role_var,
                values=ROLES,
                state="readonly",
            ).pack(**pad)

        def save() -> None:
            if not validate_email(email_var.get()):
                messagebox.showwarning(
                    "Validation", "Invalid email.", parent=dialog
                )
                return
            new_password = password_var.get().strip() or None
            if new_password and len(new_password) < PASSWORD_MIN_LEN:
                messagebox.showwarning(
                    "Validation",
                    f"Password must be at least {PASSWORD_MIN_LEN} characters.",
                    parent=dialog,
                )
                return
            role = role_var.get() if self.session.is_admin else None
            success, message = self.db.update_user(
                self.session.user_id,
                email_var.get(),
                phone_var.get(),
                role=role,
                password=new_password,
            )
            if success:
                updated = self.db.get_user_by_id(self.session.user_id)
                self.session.login(updated)
                messagebox.showinfo("Success", message, parent=dialog)
                dialog.destroy()
            else:
                messagebox.showerror("Error", message, parent=dialog)

        ttk.Button(dialog, text="Save Changes", command=save).pack(pady=16)

    def _show_admin_panel(self) -> None:
        if not self.session.is_admin:
            messagebox.showerror("Access Denied", "Admin access only.")
            return

        window = tk.Toplevel(self.root)
        window.title("Admin Panel")
        window.geometry("920x520")
        window.configure(bg=COLORS["bg"])

        toolbar = ttk.Frame(window, padding=12)
        toolbar.pack(fill=tk.X)

        search_var = tk.StringVar()
        role_var = tk.StringVar(value="All")

        ttk.Label(toolbar, text="Search:").pack(side=tk.LEFT)
        ttk.Entry(toolbar, textvariable=search_var, width=24).pack(
            side=tk.LEFT, padx=6
        )
        ttk.Label(toolbar, text="Role:").pack(side=tk.LEFT, padx=(12, 0))
        ttk.Combobox(
            toolbar,
            textvariable=role_var,
            values=["All"] + list(ROLES),
            state="readonly",
            width=10,
        ).pack(side=tk.LEFT, padx=6)

        table_frame = ttk.Frame(window, padding=12)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("id", "username", "email", "phone", "role", "created_at")
        tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", height=15
        )
        widths = (50, 120, 200, 110, 80, 150)
        for col, width in zip(columns, widths):
            tree.heading(col, text=col.replace("_", " ").title())
            tree.column(
                col,
                width=width,
                anchor="center" if col == "id" else "w",
            )

        scrollbar = ttk.Scrollbar(
            table_frame, orient=tk.VERTICAL, command=tree.yview
        )
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def refresh() -> None:
            for item in tree.get_children():
                tree.delete(item)
            role_filter = None if role_var.get() == "All" else role_var.get()
            users = self.db.get_all_users(
                role_filter, search_var.get() or None
            )
            for user in users:
                tree.insert(
                    "",
                    tk.END,
                    iid=str(user["id"]),
                    values=(
                        user["id"],
                        user["username"],
                        user["email"],
                        user["phone"] or "",
                        user["role"],
                        user["created_at"],
                    ),
                )

        def delete_selected() -> None:
            selected = tree.selection()
            if not selected:
                messagebox.showwarning(
                    "Admin", "Select a user to delete.", parent=window
                )
                return
            user_id = int(selected[0])
            if user_id == self.session.user_id:
                messagebox.showwarning(
                    "Admin",
                    "Cannot delete your own account from here.",
                    parent=window,
                )
                return
            if messagebox.askyesno(
                "Confirm", "Delete selected user?", parent=window
            ):
                success, message = self.db.delete_user(user_id)
                if success:
                    refresh()
                    messagebox.showinfo("Success", message, parent=window)
                else:
                    messagebox.showerror("Error", message, parent=window)

        def export_csv() -> None:
            path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                parent=window,
            )
            if not path:
                return
            try:
                role_filter = (
                    None if role_var.get() == "All" else role_var.get()
                )
                self.db.export_users_csv(
                    path, role_filter, search_var.get() or None
                )
                messagebox.showinfo(
                    "Export", f"Exported successfully:\n{path}", parent=window
                )
            except OSError as exc:
                messagebox.showerror("Export", str(exc), parent=window)

        ttk.Button(toolbar, text="Refresh", command=refresh).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(toolbar, text="Delete Selected", command=delete_selected).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(toolbar, text="Export CSV", command=export_csv).pack(
            side=tk.LEFT, padx=4
        )

        refresh()

    # -------------------------------------------------------------------------
    # Event handlers
    # -------------------------------------------------------------------------
    def _handle_login(self) -> None:
        username = self.login_username.get().strip()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showwarning("Login", "Enter username and password.")
            return

        locked, lock_message = self.db.is_locked(username)
        if locked:
            messagebox.showerror("Locked", lock_message)
            return

        user = self.db.get_user_by_username(username)
        if user is None or not self.db.verify_password(password, user["password"]):
            self.db.record_failed_login(username)
            attempt_row = self.db.get_login_attempts(username)
            attempts = attempt_row["attempts"] if attempt_row else 0
            remaining = max(0, MAX_LOGIN_ATTEMPTS - attempts)
            if remaining == 0:
                messagebox.showerror(
                    "Locked",
                    f"Too many failed attempts. "
                    f"Locked for {LOCKOUT_MINUTES} minutes.",
                )
            else:
                messagebox.showerror(
                    "Login Failed",
                    f"Invalid credentials. {remaining} attempt(s) left.",
                )
            return

        self.db.clear_login_attempts(username)
        self.session.login(user)
        self.show_dashboard()

    def _handle_register(self) -> None:
        username = self.reg_username.get().strip()
        email = self.reg_email.get().strip()
        password = self.reg_password.get()
        phone = self.reg_phone.get().strip()
        role = self.reg_role.get()

        if not username or not email or not password:
            messagebox.showwarning(
                "Register", "Username, email, and password are required."
            )
            return
        if not validate_username(username):
            messagebox.showwarning(
                "Register",
                "Username must be 3-30 chars (letters, numbers, underscore).",
            )
            return
        if not validate_email(email):
            messagebox.showwarning("Register", "Invalid email format.")
            return
        if len(password) < PASSWORD_MIN_LEN:
            messagebox.showwarning(
                "Register",
                f"Password must be at least {PASSWORD_MIN_LEN} characters.",
            )
            return

        success, message = self.db.create_user(
            username, email, password, phone, role
        )
        if success:
            messagebox.showinfo("Success", message)
            self.show_login_screen()
        else:
            messagebox.showerror("Register", message)

    def _handle_generate_token(self) -> None:
        username = self.forgot_username.get().strip()
        if not username:
            messagebox.showwarning("Forgot", "Enter username.")
            return
        success, message, token = self.db.create_reset_token(username)
        if success:
            self.forgot_token_label.set(f"Token: {token}")
            messagebox.showinfo("Token", f"{message}\n\nYour token: {token}")
        else:
            messagebox.showerror("Forgot", message)

    def _handle_reset_password(self) -> None:
        username = self.forgot_username.get().strip()
        token = self.forgot_token.get().strip()
        new_password = self.forgot_new_password.get()

        if not username or not token or not new_password:
            messagebox.showwarning("Reset", "Fill all fields.")
            return
        if len(new_password) < PASSWORD_MIN_LEN:
            messagebox.showwarning(
                "Reset",
                f"Password must be at least {PASSWORD_MIN_LEN} characters.",
            )
            return

        success, message = self.db.reset_password_with_token(
            username, token, new_password
        )
        if success:
            messagebox.showinfo("Success", message)
            self.show_login_screen()
        else:
            messagebox.showerror("Reset", message)

    def _handle_delete_self(self) -> None:
        if not messagebox.askyesno(
            "Delete Account",
            "This permanently deletes your account. Continue?",
        ):
            return
        success, message = self.db.delete_user(self.session.user_id)
        if success:
            self.session.logout()
            messagebox.showinfo("Deleted", message)
            self.show_login_screen()
        else:
            messagebox.showerror("Error", message)

    def _handle_logout(self) -> None:
        self.session.logout()
        self.show_login_screen()


# =============================================================================
# ENTRY POINT
# =============================================================================
def main() -> None:
    root = tk.Tk()
    try:
        UserManagementApp(root)
        root.mainloop()
    except Exception as exc:
        messagebox.showerror("Fatal Error", str(exc))


if __name__ == "__main__":
    main()