import requests
import hashlib
import sys

def request_api_data(query_char):
    """Request data from the Pwned Passwords API range endpoint.

    Args:
        query_char (str): The first 5 characters of the SHA-1 hash of a password.

    Raises:
        RuntimeError: If the API request fails (status code is not 200).

    Returns:
        requests.Response: The response object from the API containing hash tails and counts.
    """
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again.')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    """Check if a given hash tail exists in the list of leaked hashes and return its count.

    Args:
        hashes (requests.Response): The response object from the Pwned Passwords API range endpoint.
                    Its text content should be a list of hash tails and counts
                    separated by colons and newlines (e.g., 'HASH_TAIL:COUNT\n...').
        hash_to_check (str): The tail part of the SHA-1 hash (everything after the first 5 characters).

    Returns:
        int: The number of times the password corresponding to the hash_to_check was found
             in the breaches, or 0 if not found in the provided hashes.
    """
    # Split the response text into lines, then split each line by ':'
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    """Check a password against the Pwned Passwords API to see if it's been compromised.

    It calculates the SHA-1 hash of the password, queries the API using the
    first 5 characters of the hash, and then checks the returned hash tails
    to see if the full hash tail matches any known compromised passwords.

    Args:
        password (str): The password to check.

    Returns:
        int: The number of times the password was found in breaches, or 0 if not found.
    """
    # Calculate the SHA-1 hash of the password (case-insensitive comparison is typical for hashes)
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def main(args):
    """Main function to process command-line arguments and check passwords.

    Iterates through the provided passwords (typically from sys.argv), checks
    each one against the Pwned Passwords API, and prints the result.

    Args:
        args (list): A list of password strings to check.

    Returns:
        str: A string indicating completion ('Done!'). Exits via sys.exit() normally.
    """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password.')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'Done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
