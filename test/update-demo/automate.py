import subprocess
import os

# Function to execute a command and capture its output
def execute_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if result.returncode != 0:
        print(f"Error executing command: {command}")
        print(result.stderr.decode())
        return None
    return result.stdout.decode()

# Main function to orchestrate the process
def main():
    # Loop for a thousand times
    for i in range(1000):
        print(f"Iteration {i+1}:")

        # Generate key pair using kymain.c
        key_gen_output = execute_command("./kymain")
        if key_gen_output is None:
            return

        # Extract the generated key from the output (assuming kymain prints the key to stdout)
        key = key_gen_output.strip()  # Assuming the key is a string and needs to be stripped

        # Encrypt file using aes-encrypt.c with the generated key
        aes_encrypt_output = execute_command(f"./aes-encrypt {key} input_file.txt")  # Replace input_file.txt with your input file
        if aes_encrypt_output is None:
            return

        # Generate HMAC tag using hmac-encrypt.c
        hmac_tag = execute_command("./hmac-encrypt")
        if hmac_tag is None:
            return

        # Concatenate HMAC tag with encrypted file
        with open("encrypted_file.txt", "ab") as file:
            file.write(hmac_tag.encode())

        # Sign concatenated data using dil-sign.c
        sign_output = execute_command("./dil-sign encrypted_file.txt")
        if sign_output is None:
            return

        print("Iteration completed successfully.")

    print("All iterations completed.")

if __name__ == "__main__":
    main()
