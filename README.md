# Hash-analayzer
The Hash Analyzer script is a Ruby program designed to analyze and identify various types of cryptographic hash functions based on the length and format of the input hash. It supports a range of hash algorithms and provides information about each identified hash type.

# Features and Specifications

he script analyzes the input hash and determines its type based on its length and structure.
It supports the following hash algorithms: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, bcrypt, SHA-256 Crypt, SHA-512 Crypt, and Whirlpool.
The script can also detect and analyze Base64-encoded, URL-encoded, and HTML-encoded hashes.
For each identified hash type, the script provides relevant information, including the hash type, length, and a descriptive message.
The script displays the analysis results in a user-friendly and formatted manner.

# Usage

1- The user provides an input hash.

2- The user can select the language (Arabic or English) in which to display the analysis results.

3- The script identifies the hash type, displays relevant information, and provides a descriptive message about the hash type.

4- If the hash is Base64-encoded, the script decodes and displays the original decoded hash value.

# How to Run

-1 Install Ruby on your system if it is not already installed.

2- Copy the script and save it as a .rb file (e.g., hash_analyzer.rb).

3- Open a terminal or command prompt.

4- Navigate to the directory where the script is saved.

5- Run the script using the command: ruby hash_analyzer.rb.

# Notes

The script provides a flexible way to support both Arabic and English languages. It uses conditionals to display messages in the selected language.
The script makes use of regular expressions to match specific hash patterns and determine the hash type.

# Disclaimer
This script is provided for educational and informational purposes only. Cryptographic hash analysis is a complex subject, and this script may not cover all possible hash variations. Use this script responsibly and ensure that you have the appropriate permissions to analyze hashes.

Please remember to respect software licenses and guidelines when using and sharing this script on platforms like GitHub.
