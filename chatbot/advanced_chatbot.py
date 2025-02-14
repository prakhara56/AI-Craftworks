from .base_chatbot import BaseChatbot

class AdvancedChatbot(BaseChatbot):
    """
    An advanced chatbot class inheriting from BaseChatbot.
    """

    def process_user_input(self, prompt):
        """
        Extend the base method to include additional processing logic.

        Args:
            prompt (str): The user's input message.
        """
        super().process_user_input(prompt)
        self.log_user_input(prompt)

    def log_user_input(self, prompt):
        """
        Log user input for analytics or debugging.

        Args:
            prompt (str): The user's input message.
        """
        # Placeholder for logging implementation
        print(f"Logged input: {prompt}")