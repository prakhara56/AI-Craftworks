import streamlit as st
from pymongo import MongoClient
import bcrypt
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- MongoDB Connection & Indexes for Auth ---
mongo_uri = st.secrets["MONGO_URI"] or os.getenv("MONGO_URI", "mongodb://your_username:your_password@your_host:your_port/")
client = MongoClient(mongo_uri)
database_name = st.secrets["LOGIN_DB_NAME"] or os.getenv("LOGIN_DB_NAME", "your_database_name")
db = client[database_name]
users_collection = db["users"]

# Ensure uniqueness on username and email
users_collection.create_index("username", unique=True)
users_collection.create_index("email", unique=True)

# --- Helper Functions ---
def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_user(username: str, password: str) -> bool:
    """Verify the given username and password against the stored record."""
    user = users_collection.find_one({"username": username})
    if user:
        stored_hash = user.get("password").encode("utf-8")
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    return False


def register_user(username: str, full_name: str, email: str, password: str):
    """Register a new user if the username or email isn’t already taken."""
    if users_collection.find_one({"username": username}):
        return False, "Username already exists."
    if users_collection.find_one({"email": email}):
        return False, "Email already in use."
    hashed_pw = hash_password(password)
    users_collection.insert_one({
        "username": username,
        "full_name": full_name,
        "email": email,
        "password": hashed_pw
    })
    return True, "Registration successful."


def reset_password(username: str, email: str, new_password: str):
    """Reset the password for the given username if the email matches."""
    user = users_collection.find_one({"username": username, "email": email})
    if not user:
        return False, "Username and email do not match our records."
    new_hashed = hash_password(new_password)
    users_collection.update_one({"username": username}, {"$set": {"password": new_hashed}})
    return True, "Password reset successful."


# --- Modular Authentication UI ---
class AuthUI:
    @staticmethod
    def render_auth_page():
        """Render the authentication page with options for login, register, or forgot password."""
        st.markdown("""
            <style>
                .stApp {background-color: #f4f4f4;}
                .stTextInput, .stButton, .stRadio {text-align: center; width: 100%;}
                .stForm {padding: 20px; border-radius: 10px; background: white; box-shadow: 2px 2px 10px rgba(0,0,0,0.1);}
            </style>
        """, unsafe_allow_html=True)

        st.title("🔐 User Authentication Portal")
        auth_mode = st.radio("Select an option:", ("Login", "Register", "Forgot Password"))
        
        if auth_mode == "Login":
            AuthUI.render_login()
        elif auth_mode == "Register":
            AuthUI.render_register()
        elif auth_mode == "Forgot Password":
            AuthUI.render_forgot_password()

    @staticmethod
    def render_login():
        st.header("🔑 Login")
        with st.form("login_form", clear_on_submit=True):
            username = st.text_input("👤 Username")
            password = st.text_input("🔒 Password", type="password")
            login_submit = st.form_submit_button("🚀 Login")
        
        if login_submit:
            if verify_user(username, password):
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.success("✅ Logged in successfully!")
                st.rerun()
            else:
                st.error("❌ Incorrect username or password")

    @staticmethod
    def render_register():
        st.header("📝 Register")
        with st.form("register_form", clear_on_submit=True):
            username = st.text_input("👤 Choose a Username")
            full_name = st.text_input("📛 Enter your Full Name")
            email = st.text_input("📧 Enter your Email")
            password = st.text_input("🔑 Choose a Password", type="password")
            confirm_password = st.text_input("🔑 Confirm Password", type="password")
            register_submit = st.form_submit_button("📝 Register")
        
        if register_submit:
            if password != confirm_password:
                st.error("❌ Passwords do not match")
            else:
                success, message = register_user(username, full_name, email, password)
                if success:
                    st.success("✅ " + message)
                    st.info("You can now log in using your credentials.")
                else:
                    st.error("❌ " + message)

    @staticmethod
    def render_forgot_password():
        st.header("🔄 Reset Password")
        with st.form("forgot_form", clear_on_submit=True):
            username = st.text_input("👤 Enter your Username")
            email = st.text_input("📧 Enter your registered Email")
            new_password = st.text_input("🔑 Enter new Password", type="password")
            confirm_new_password = st.text_input("🔑 Confirm new Password", type="password")
            forgot_submit = st.form_submit_button("🔄 Reset Password")
        
        if forgot_submit:
            if new_password != confirm_new_password:
                st.error("❌ Passwords do not match")
            else:
                success, message = reset_password(username, email, new_password)
                if success:
                    st.success("✅ " + message)
                    st.info("Please log in with your new password.")
                else:
                    st.error("❌ " + message)
    
    @staticmethod
    def render_logout():
        """Provide a logout button to return to the login page."""
        if st.button("🚪 Logout"):
            st.session_state.clear()
            st.rerun()
