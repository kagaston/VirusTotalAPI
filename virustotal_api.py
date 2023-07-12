import argparse
import logging
import os
from dotenv import load_dotenv
import requests

from src.api_key_provider import APIKeyProvider
from src.formatters import JSONFormatter


class VirusTotalAPI:
    """
    Class for interacting with the VirusTotal API.
    """

    def __init__(self, api_key):
        """
        Initialize the VirusTotal API client.

        Args:
            api_key (str): Your VirusTotal API key.
        """
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {'x-apikey': api_key}

    def _make_request(self, method, endpoint, data=None, files=None):
        """
        Make an HTTP request to the VirusTotal API.

        Args:
            method (str): The HTTP method (GET, POST, etc.).
            endpoint (str): The API endpoint.
            data (dict): The request payload data (optional).
            files (dict): The files to be uploaded (optional).

        Returns:
            dict: The JSON response from the API.

        Raises:
            requests.HTTPError: If the request encounters an error.
        """
        url = self.base_url + endpoint
        response = requests.request(method, url, headers=self.headers, data=data, files=files)
        response.raise_for_status()
        return response.json()

    def file_scan(self, file_path):
        """
        Submit a file for scanning.

        Args:
            file_path (str): The path to the file.

        Returns:
            dict: The JSON response from the API.
        """
        endpoint = '/files'
        files = {'file': open(file_path, 'rb')}
        return self._make_request('POST', endpoint, files=files)

    def url_scan(self, url):
        """
        Submit a URL for scanning.

        Args:
            url (str): The URL to scan.

        Returns:
            dict: The JSON response from the API.
        """
        endpoint = '/urls'
        data = {'url': url}
        return self._make_request('POST', endpoint, data=data)

    def ip_report(self, ip_address):
        """
        Retrieve an IP address report.

        Args:
            ip_address (str): The IP address.

        Returns:
            dict: The JSON response from the API.
        """
        endpoint = f'/ip_addresses/{ip_address}'
        return self._make_request('GET', endpoint)

    def domain_report(self, domain):
        """
        Retrieve a domain report.

        Args:
            domain (str): The domain.

        Returns:
            dict: The JSON response from the API.
        """
        endpoint = f'/domains/{domain}'
        return self._make_request('GET', endpoint)


def file_scan(api_key, file_path):
    """
    Submit a file for scanning.

    Args:
        api_key (str): Your VirusTotal API key.
        file_path (str): The path to the file.
    """
    api = VirusTotalAPI(api_key)
    result = api.file_scan(file_path)
    logging.info(result)


def url_scan(api_key, url):
    """
    Submit a URL for scanning.

    Args:
        api_key (str): Your VirusTotal API key.
        url (str): The URL to scan.
    """
    api = VirusTotalAPI(api_key)
    result = api.url_scan(url)
    logging.info(result)


def ip_report(api_key, ip_address):
    """
    Retrieve an IP address report.

    Args:
        api_key (str): Your VirusTotal API key.
        ip_address (str): The IP address.
    """
    api = VirusTotalAPI(api_key)
    result = api.ip_report(ip_address)
    logging.info(result)


def domain_report(api_key, domain):
    """
    Retrieve a domain report.

    Args:
        api_key (str): Your VirusTotal API key.
        domain (str): The domain.
    """
    api = VirusTotalAPI(api_key)
    result = api.domain_report(domain)
    logging.info(result)


def configure_logging():
    """
    Configures the logging module to write logs to a file with a JSON formatter.
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    log_file_name = "virustotal-log.json"
    formatter = JSONFormatter()
    file_handler = logging.FileHandler(log_file_name)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    return logger


def main():
    """
    Main function for command line execution.
    """

    configure_logging()

    parser = argparse.ArgumentParser(description='VirusTotal API Client')
    # parser.add_argument('--api-key', help='Your VirusTotal API key')
    subparsers = parser.add_subparsers()

    file_scan_parser = subparsers.add_parser('file-scan', help='Submit a file for scanning')
    file_scan_parser.add_argument('file_path', help='Path to the file')
    file_scan_parser.set_defaults(func=lambda args: file_scan(api_key, args.file_path))

    url_scan_parser = subparsers.add_parser('url-scan', help='Submit a URL for scanning')
    url_scan_parser.add_argument('url', help='URL to scan')
    url_scan_parser.set_defaults(func=lambda args: url_scan(api_key, args.url))

    ip_report_parser = subparsers.add_parser('ip-report', help='Retrieve IP address report')
    ip_report_parser.add_argument('ip_address', help='IP address')
    ip_report_parser.set_defaults(func=lambda args: ip_report(api_key, args.ip_address))

    domain_report_parser = subparsers.add_parser('domain-report', help='Retrieve domain report')
    domain_report_parser.add_argument('domain', help='Domain')
    domain_report_parser.set_defaults(func=lambda args: domain_report(api_key, args.domain))

    args = parser.parse_args()

    # Loads the API key from the environment variable.
    api_key_name = "VIRUSTOTAL_API_KEY"
    api_key_provider = APIKeyProvider(api_key_name)
    api_key = api_key_provider.get_api_key()

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
