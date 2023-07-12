# OpenAI ChatBot

This repository contains code and resources for building python collection script that leverages the VirusTotal API.

## Overview

This is a collection script that is to be used for interaction with the VirusTotal API.

## Features

- This script allows for the ability to leverage the Virustotal api in a fast and effective manner
- The script allows the user to:
  - Scan files
  - submit urls
  - search ip addresses
  - pull domain reports

## Requirements

To use the VirusTotal API Script, ensure you have the following:

- Python 3.x
- VirusTotal API key

## Getting Started

1. Clone the repository:

   ```shell
   git clone https://github.com/kagaston/VirusTotalAPI.git
   ```

2. Install the required dependencies:
    ```shell
    pip install -r requirements.txt
    ```

3. Set up your OpenAI API key:
   Visit the VirusTotal website to sign up for an API key.
   Set the VIRUSTOTAL_API_KEY environment variable or update the config.py file with your API key.
   Explore the code and files provided in the repository to understand how to use and customize the chatbot.

## Usage

To use the VirusTotal collection script, follow these steps:

1. Install requirements:
    ```shell
    pip install requirements
    ```
2. Run the script
    ```shell
    python virustotal_api.py url-scan google.com
    ```

# Contributing

Contributions to the virusTotal collection script are welcome!

If you encounter any issues or have suggestions for improvements, feel free to submit a pull request or open an issue on the repository.

# License

This project is licensed under the MIT License.