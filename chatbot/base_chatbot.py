import streamlit as st
from .session_manager import SessionManager
from .ui import ChatUI


class BaseChatbot:
    """
    A base class for building chatbots with multiple LLMs.
    """

    def __init__(self, llm_clients):
        """
        Initialize the chatbot with LLM clients.

        Args:
            llm_clients (dict): Dictionary of available LLM clients.
        """
        self.llm_clients = llm_clients
        self.valid_llms = list(llm_clients.keys())
        self.current_client = None
        SessionManager.initialize(self.valid_llms)

    def process_user_input(self, prompt):
        """
        Process user input and generate a response from the selected LLM.

        Args:
            prompt (str): The user's input message.
        """

        # Append user input to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Generate assistant's response
        with st.chat_message("assistant"):
            try:
                response_stream = self.current_client.stream(
                    [
                        {"role": m["role"], "content": m["content"]}
                        for m in st.session_state.messages
                    ]
                )
                
                response_content = st.write_stream(response_stream)
            except Exception as e:
                response_content = f"Error: {e}"
                st.error(response_content)
        st.session_state.messages.append({"role": "assistant", "content": response_content})

    def run(self):
        """
        Main method to run the chatbot application.
        """
        st.title("ChatGPT-like Clone")

        # Update current client based on selection
        self.current_client = self.llm_clients[st.session_state.selected_llm]

        # Render sidebar and chat history
        ChatUI.render_sidebar(self.valid_llms)
        ChatUI.render_chat_history()

        # Chat input section
        if prompt := st.chat_input("Type 'hi' to start or ask anything!"):
            self.process_user_input(prompt)