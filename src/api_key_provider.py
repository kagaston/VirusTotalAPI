from dotenv import load_dotenv
import os


class EnvironmentVariableProvider:
    """
    Class for retrieving an API key from environment variables.

    This class provides a way to retrieve an API key by checking the environment variables.
    If the API key is not found, a ValueError is raised.

    Parameters:
    - api_key_name (str): The name of the API key variable.

    Methods:
    - get_api_key(): Retrieves the API key from the environment variables.
                     Returns the API key if found, otherwise raises a ValueError.
    """

    def __init__(self, api_key_name):
        self.api_key_name = api_key_name

    def get_api_key(self):
        """
        Retrieves the API key from the environment variables.

        Returns:
            str: The API key if found in the environment variables.

        Raises:
            ValueError: If the API key is not found in the environment variables.
        """

        api_key = os.environ.get(self.api_key_name)

        if api_key is None:
            raise ValueError(f"{self.api_key_name} not found in environment variables")

        return api_key.strip('\"')


class DotEnvFileProvider:
    """
    Class for retrieving an API key from a .env file.

    This class provides a way to retrieve an API key by checking a .env file.
    If the API key is not found, None is returned.

    Parameters:
    - file_path (str): The path to the .env file.

    Methods:
    - get_api_key(api_key_name): Retrieves the API key from the .env file.
                                 Returns the API key if found, otherwise returns None.
    """

    def __init__(self, file_path):
        self.file_path = file_path

    def get_api_key(self, api_key_name):
        """
        Retrieves the API key from the .env file.

        Args:
            api_key_name (str): The name of the API key variable.

        Returns:
            str: The API key if found in the .env file, otherwise returns None.
        """

        try:
            with open(self.file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line.startswith(api_key_name + '='):
                        return line[len(api_key_name) + 1:]
        except FileNotFoundError:
            pass

        return None


class APIKeyProvider:
    """
    Utility class for retrieving an API key from environment variables or a .env file.

    This class provides a way to retrieve an API key by checking both the environment variables
    and a .env file. If the API key is not found in either location, a ValueError is raised.

    Parameters:
    - api_key_name (str): The name of the API key variable.

    Methods:
    - get_api_key(): Retrieves the API key from the environment variables or the .env file.
                     Returns the API key if found, otherwise raises a ValueError.
    """

    def __init__(self, api_key_name):
        """
        Initializes the APIKeyProvider class.

        Args:
            api_key_name (str): The name of the API key variable.
        """

        self.environment_provider = EnvironmentVariableProvider(api_key_name)
        self.dotenv_provider = DotEnvFileProvider(".env")
        self.api_key_name = api_key_name

    def get_api_key(self):
        """
        Retrieves the API key from the environment variables or the .env file.

        Returns:
            str: The API key if found in the environment variables or the .env file.

        Raises:
            ValueError: If the API key is not found in the environment variables or the .env file.
        """

        try:
            api_key = self.environment_provider.get_api_key()
        except ValueError:
            api_key = self.dotenv_provider.get_api_key(self.api_key_name)

        if api_key is None:
            raise ValueError(f"{self.api_key_name} not found in environment variables or .env file")

        return api_key.strip('\"')