import streamlit as st
from .session_manager import SessionManager


class ChatUI:
    """
    Handles the Streamlit UI for the chatbot.
    """

    @staticmethod
    def render_sidebar(valid_llms):
        """
        Render the sidebar for selecting LLM and clearing chat history.

        Args:
            valid_llms (list): A list of valid LLM names initialized.
        """
        with st.sidebar:
            st.title("🤖💬 Chatbot")

            if valid_llms:
                # Dropdown to choose LLM
                st.session_state.selected_llm = st.selectbox(
                    "Choose LLM:", options=valid_llms, index=0
                )

                SessionManager.reset_if_llm_changed()

                # Display the selected LLM
                st.write(f"### Selected LLM: {st.session_state.selected_llm}")

                # Button to clear chat history
                if st.button("Clear Chat History"):
                    st.session_state.messages = []
                    st.success("Chat history cleared!")
            else:
                st.error("No LLMs are available. Please check your configuration.")
            
            from .auth import AuthUI
            AuthUI.render_logout()
    @staticmethod
    def render_chat_history():
        """
        Render the chat history on the interface.
        """
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])