import streamlit as st
from pymongo import MongoClient
import bcrypt
import os
from typing import Tuple
from dotenv import load_dotenv

load_dotenv()

# --- Helper Functions Using Best Practices ---

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    The result is decoded to a string for storage.
    """
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

def verify_user(username: str, password: str) -> bool:
    """
    Verify that the provided username and password match the stored record.
    """
    user = users_collection.find_one({"username": username})
    if user:
        stored_hash = user.get("password").encode('utf-8')
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
    return False

def register_user(username: str, full_name: str, email: str, password: str) -> Tuple[bool, str]:
    """
    Register a new user if the username or email is not already taken.
    The password is stored securely using bcrypt.
    """
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

def reset_password(username: str, email: str, new_password: str) -> Tuple[bool, str]:
    """
    Reset the password for the given username if the provided email matches.
    """
    user = users_collection.find_one({"username": username, "email": email})
    if not user:
        return False, "Username and email do not match our records."
    new_hashed = hash_password(new_password)
    users_collection.update_one({"username": username}, {"$set": {"password": new_hashed}})
    return True, "Password reset successful."

# --- Secure MongoDB Connection ---
# Use an environment variable for your MongoDB URI.
mongo_uri = os.getenv("MONGO_URI", "mongodb://your_username:your_password@your_host:your_port/")
client = MongoClient(mongo_uri)
database_name = os.getenv("LOGIN_DB_NAME", "your_database_name")
db = client[database_name]
users_collection = db["users"]

# Create unique indexes on username and email to enforce uniqueness at the DB level.
users_collection.create_index("username", unique=True)
users_collection.create_index("email", unique=True)

# --- Streamlit App ---

st.title("User Authentication Portal")

# Let the user select an option
auth_mode = st.radio("Select Option:", ("Login", "Register", "Forgot Password"))

# Session state variables for authentication status and username
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""

if auth_mode == "Login":
    st.header("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_submit = st.form_submit_button("Login")
    if login_submit:
        if verify_user(username, password):
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
            st.success("Logged in successfully!")
            st.rerun()  # Refresh to display the chatbot UI
        else:
            st.error("Incorrect username or password")

elif auth_mode == "Register":
    st.header("Register")
    with st.form("register_form"):
        username = st.text_input("Choose a Username")
        full_name = st.text_input("Enter your Full Name")
        email = st.text_input("Enter your Email")
        password = st.text_input("Choose a Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        register_submit = st.form_submit_button("Register")
    if register_submit:
        if password != confirm_password:
            st.error("Passwords do not match")
        else:
            success, message = register_user(username, full_name, email, password)
            if success:
                st.success(message)
                st.info("You can now log in using your credentials.")
            else:
                st.error(message)

elif auth_mode == "Forgot Password":
    st.header("Reset Password")
    with st.form("forgot_form"):
        username = st.text_input("Enter your Username")
        email = st.text_input("Enter your registered Email")
        new_password = st.text_input("Enter new Password", type="password")
        confirm_new_password = st.text_input("Confirm new Password", type="password")
        forgot_submit = st.form_submit_button("Reset Password")
    if forgot_submit:
        if new_password != confirm_new_password:
            st.error("Passwords do not match")
        else:
            success, message = reset_password(username, email, new_password)
            if success:
                st.success(message)
                st.info("Please log in with your new password.")
            else:
                st.error(message)

# --- Chatbot UI (Accessible Only When Logged In) ---
if st.session_state.get("logged_in"):
    # Retrieve user details from MongoDB
    user_details = users_collection.find_one({"username": st.session_state["username"]})
    st.session_state.user_details = user_details
    # if user_details:
    #     st.subheader("Your Profile Details")
    #     st.write(f"**Username:** {user_details.get('username', 'N/A')}")
    #     st.write(f"**Full Name:** {user_details.get('full_name', 'N/A')}")
    #     st.write(f"**Email:** {user_details.get('email', 'N/A')}")
    
    st.title("Chatbot")
    st.write(f"Welcome, {st.session_state.user_details['full_name']}!")
    # Replace this simple interface with your actual chatbot logic.
    user_input = st.text_input("You: ", key="chat_input")
    if st.button("Send"):
        response = f"Echo: {user_input}"  # Dummy response for demonstration
        st.write(response)
