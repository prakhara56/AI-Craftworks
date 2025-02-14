from langchain_openai import AzureChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_mistralai import ChatMistralAI
import streamlit as st


class LLMClients:
    """
    Manages the initialization and validation of LLM clients based on available secrets.
    """

    @staticmethod
    def initialize_clients(secrets):
        """
        Initialize valid LLM clients based on available secrets.

        Args:
            secrets (dict): Secret keys and configurations for LLMs.

        Returns:
            dict: A dictionary of initialized LLM clients.
        """
        initialized_clients = {}

        # Check and initialize Azure OpenAI if secrets are available
        if all(
            key in secrets
            for key in [
                "AZURE_OPENAI_DEPLOYMENT_NAME",
                "AZURE_OPENAI_ENDPOINT",
                "AZURE_OPENAI_VERSION",
                "AZURE_OPENAI_API_KEY",
            ]
        ):
            try:
                azure_client = AzureChatOpenAI(
                    azure_deployment=secrets["AZURE_OPENAI_DEPLOYMENT_NAME"],
                    azure_endpoint=secrets["AZURE_OPENAI_ENDPOINT"],
                    api_version=secrets["AZURE_OPENAI_VERSION"],
                    api_key=secrets["AZURE_OPENAI_API_KEY"],
                )
                initialized_clients["OpenAI"] = azure_client
            except Exception as e:
                st.error(f"Failed to initialize Azure OpenAI: {e}")

        # Check and initialize Google Gemini if secrets are available
        if "GOOGLE_API_KEY" in secrets:
            try:
                gemini_client = ChatGoogleGenerativeAI(
                    model="gemini-1.5-flash",
                    api_key=secrets["GOOGLE_API_KEY"],
                )
                initialized_clients["Gemini"] = gemini_client
            except Exception as e:
                st.error(f"Failed to initialize Google Gemini: {e}")
        if "MISTRAL_API_KEY" in secrets:
            try:
                mistral_client = ChatMistralAI(
                    model="mistral-large-latest",
                    api_key=secrets["MISTRAL_API_KEY"],
                )
                initialized_clients["MistralAI"] = mistral_client
            except Exception as e:
                st.error(f"Failed to initialize Mistral: {e}")

        # Warn if no LLMs are initialized
        if not initialized_clients:
            st.warning("No LLMs were initialized. Please check your secrets configuration.")

        return initialized_clients