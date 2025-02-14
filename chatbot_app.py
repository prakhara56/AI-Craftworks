import streamlit as st
from chatbot.base_chatbot import BaseChatbot
from chatbot.llm_clients import LLMClients
from chatbot.auth import AuthUI  # import our modular login UI

def main():
    # Initialize login status if not already set
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False

    # If user is not logged in, render the authentication page
    if not st.session_state["logged_in"]:
        AuthUI.render_auth_page()
    else:
        # Optionally, display user details in the sidebar
        # (Assuming your auth module stores username in session_state)
        # You might add a method in AuthUI to retrieve user details if needed.

        # Initialize LLM clients
        llm_clients = LLMClients.initialize_clients(st.secrets)
        # Create and run your chatbot
        chatbot = BaseChatbot(llm_clients)
        chatbot.run()

if __name__ == "__main__":
    main()
