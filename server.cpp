#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <openssl/sha.h>   // For SHA-256 hashing
#include <openssl/err.h>
#include <iomanip>         // For setw, setfill
#include <cstdlib>         // For rand()
#include <ctime>
#include <regex>           // For email validation check
#include <random>
#include <openssl/aes.h>   // For AES encryption/decryption
#include <openssl/rand.h>   // For random bytes generation
#include <openssl/evp.h>

using namespace std;

// Diffie-Hellman parameters
const int prime = 23;  // A prime number
const int base = 5;    // A primitive root modulo prime

// AES parameters
const int AES_KEY_SIZE = 128; // AES key size in bits - 16 bytes

// Function declarations
string generate_salt(int length = 16);
string hash_password(const string& password, const string& salt);
bool is_username_unique(const string& username);
bool is_email_unique(const string& email);
bool is_valid_email(const string& email);
void store_credentials(const string& email, const string& username, const string& hashed_password, const string& salt);
void validate_email(int client_socket, string email);
void validate_username(int client_socket, string username);
bool register_user(string email, string username, string password) ;
bool login_user(int client_socket, unsigned char* aes_key);
int encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, const unsigned char *key, unsigned char *iv);
int decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, const unsigned char *key, const unsigned char *iv) ;
void secure_chat(int client_socket, unsigned char* aes_key) ;

// Function for modular exponentiation
int modular_pow(int base, int exp, int mod)    // result = base ^ exp mod (mod) = alpha^pr_k mod p
{
    int result = 1;
    while (exp > 0) 
    {
        if (exp % 2 == 1) 
        {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

// Function to generate a random private key
int generate_private_key()
{
    random_device rd;  
    mt19937 eng(rd());
    uniform_int_distribution<> distr(1, prime - 1);
    return distr(eng);
}

// Function to calculate public key
int calculate_public_key(int private_key)
{
    return modular_pow(base, private_key, prime);   // alpha, pr_key, p
}

// Function to compute shared secret
int compute_shared_secret(int public_key, int private_key)
{
    return modular_pow(public_key, private_key, prime);   // pub_key ^ pr_key mod p
}

void derive_aes_key(int shared_secret, unsigned char* aes_key)
{
    //unsigned char aes_key[16];
    for (int i= 0 ; i < 16 ; i++)
    {
       aes_key[i] = (shared_secret >> (8 * (15-i))) & 0xFF;  
    }
}


int main()
{
    char buf[256];
    char message[256] = "Server: ";

    cout << "\n\033[1;4;34m\t >>>>>>>>>> XYZ University Chat Server <<<<<<<<<<\n\n\033[0m";

    // create the server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    server_address.sin_addr.s_addr = INADDR_ANY;

    bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address));
    listen(server_socket, 5); // Listen for incoming connections

    while (1)
    {
        int client_socket = accept(server_socket, NULL, NULL);
        cout << "\n\033[1;32m\t" << message << "Client connected.\n\033[0m";
        pid_t new_pid = fork(); // Create a new process for each client
        if (new_pid == 0)
        {
            // Child process
            int server_private_key = generate_private_key(); // Generate server's private key
            int server_public_key = calculate_public_key(server_private_key); // Calculate server's public key

            // Send server public key to client
            send(client_socket, &server_public_key, sizeof(server_public_key), 0);

            // Receive client public key
            int client_public_key;
            recv(client_socket, &client_public_key, sizeof(client_public_key), 0);

            // Compute shared secret
            int shared_secret = compute_shared_secret(client_public_key, server_private_key);
            cout << "\n\033[1;33m Shared Secret (Server): " << shared_secret << "\033[0m" << endl;

            // Derive AES key from shared secret
            unsigned char aes_key[AES_KEY_SIZE / 8]; // 16 bytes for AES-128
            derive_aes_key(shared_secret, aes_key);
            // Print AES key
            cout << endl << "\033[1;33m AES_key (server): ";
            for (int i = 0; i < AES_KEY_SIZE / 8; i++)
            {
                cout << (int)aes_key[i] << " ";
            }
            cout << "\033[0m" << endl;

            while (true)
            {
                memset(buf, 0, sizeof(buf)); // Clear buffer
                recv(client_socket, buf, sizeof(buf), 0); // Receive data from client

                cout << "\n\033[1;36m\t Client: " << buf << "\n\033[0m";

                int command = atoi(buf); // Convert buffer to integer command

                if (command == 3)
                {
                    cout << "\n\t\033[1;31m" << message << "Client disconnected.\n\t" << message << "Waiting for connection...\n\033[0m";
                    //break; // Exit the loop if the client disconnects
                }

                switch (command)
                {
                    // Server side registration case
                    case 1:
                    {
                        // Receive IV
                        unsigned char iv[AES_BLOCK_SIZE];
                        recv(client_socket, iv, sizeof(iv), 0);

                        // Email loop
                        string email;
                        bool emailValid = false;
                        while (!emailValid)
                        {
                            // Receive the length of the encrypted email
                            int encrypted_len;
                            recv(client_socket, reinterpret_cast<char*>(&encrypted_len), sizeof(encrypted_len), 0);

                            // Receive the actual encrypted email
                            unsigned char encrypted_email[256];
                            recv(client_socket, encrypted_email, encrypted_len, 0);

                            // Decrypt the email
                            unsigned char decrypted_email[256];
                            int decrypted_len = decrypt(encrypted_email, encrypted_len, decrypted_email, aes_key, iv);

                            if (decrypted_len < 0)
                            {
                                cout << "\n\033[1;31m Decryption failed!\033[0m" << endl;
                                close(client_socket);
                                break;
                            }

                            decrypted_email[decrypted_len] = '\0'; // Null-terminate the string
                            email = reinterpret_cast<char*>(decrypted_email);
                            cout << "\n\033[1;33m Decrypted email is: " << email << "\033[0m" << endl;

                            // Validate email
                            string email_response;
                            if (is_valid_email(email) && is_email_unique(email))
                            {
                                email_response = "Email is valid and unique.";
                                emailValid = true;
                            }
                            else
                            {
                                email_response = "Invalid or already registered email.";
                            }

                            // Send response
                            send(client_socket, email_response.c_str(), email_response.length(), 0);
                        }

                        // Username loop
                        string username;
                        bool usernameValid = false;
                        while (!usernameValid)
                        {
                            // Receive the length of the encrypted username
                            int encrypted_len;
                            recv(client_socket, reinterpret_cast<char*>(&encrypted_len), sizeof(encrypted_len), 0);

                            // Receive the actual encrypted username
                            unsigned char encrypted_username[256];
                            recv(client_socket, encrypted_username, encrypted_len, 0);

                            // Decrypt the username
                            unsigned char decrypted_username[256];
                            int decrypted_len = decrypt(encrypted_username, encrypted_len, decrypted_username, aes_key, iv);

                            if (decrypted_len < 0)
                            {
                                cerr << "\n\033[1;31m Decryption failed!\033[0m" << endl;
                                close(client_socket);
                                break;
                            }

                            decrypted_username[decrypted_len] = '\0'; // Null-terminate the string
                            username = reinterpret_cast<char*>(decrypted_username);
                            cout << "\n\033[1;33m Decrypted username is: " << username << "\033[0m" << endl;

                            // Validate username
                            string username_response;
                            if (is_username_unique(username))
                            {
                                username_response = "Username is unique.";
                                usernameValid = true;
                            }
                            else
                            {
                                username_response = "Username already exists.";
                            }

                            // Send response
                            send(client_socket, username_response.c_str(), username_response.length(), 0);
                        }

                        // Password loop
                        string password;
                        while (true)
                        {
                            // Receive the length of the encrypted password
                            int encrypted_len;
                            recv(client_socket, reinterpret_cast<char*>(&encrypted_len), sizeof(encrypted_len), 0);

                            // Receive the actual encrypted password
                            unsigned char encrypted_password[256];
                            recv(client_socket, encrypted_password, encrypted_len, 0);

                            // Decrypt the password
                            unsigned char decrypted_password[256];
                            int decrypted_len = decrypt(encrypted_password, encrypted_len, decrypted_password, aes_key, iv);

                            if (decrypted_len < 0)
                            {
                                cerr << "\n\033[1;31m Decryption failed!\033[0m" << endl;
                                close(client_socket);
                                break;
                            }

                            decrypted_password[decrypted_len] = '\0'; // Null-terminate the string
                            password = reinterpret_cast<char*>(decrypted_password);
                            cout << "\n\033[1;33m Decrypted password is: " << password << "\033[0m" << endl;

                            // Register user
                            register_user(email, username, password);

                            // Send response
                            string registration_response = "Registration successful.";
                            cout << "\n\033[1;32m " << message << registration_response << "\033[0m\n" << endl;
                            send(client_socket, registration_response.c_str(), registration_response.length(), 0);

                            break;
                        }

                        break;
                    }  
                    case 2:
                    {
                        if (login_user(client_socket, aes_key))
                        {
                            secure_chat(client_socket, aes_key);
                        }
                        break;
                    }
                    case 3:
                        send(client_socket, "Exiting. Please choose again: 1 for Register, 2 for Login, 3 for Exit.", 100, 0);
                        break;
                    default:
                        send(client_socket, "Invalid command. Please choose a valid option.", 100, 0);
                        break;
                }
            }

            close(client_socket); // Close the client socket
            exit(0); // Terminate child process
        }
        else
        {
            close(client_socket); // Close the parent socket
        }
    }

    close(server_socket); // Close the server socket
    return 0; // Exit the program
}

// 1. Function to generate random salt
string generate_salt(int length)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    string salt;
    random_device rd;  
    mt19937 eng(rd());
    uniform_int_distribution<> distr(0, sizeof(charset) - 2); // Exclude null character

    for (int i = 0; i < length; i++)
    {
        salt += charset[distr(eng)];
    }
    return salt;
}

// 2. Function to hash the password using SHA-256 with salt
string hash_password(const string& password, const string& salt)
{
    string salted_password = password + salt; // Concatenate password and salt
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)salted_password.c_str(), salted_password.length(), hash);

    // Convert the hash to a hex string
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i]; // Format as hex
    }
    return ss.str(); // Return the hashed password
}

// 3. Function to check if the username is unique by searching the creds.txt file
bool is_username_unique(const string& username)
{
    ifstream file("creds.txt");
    if (file.is_open()) {
        string line;
        while (getline(file, line))
        {
            size_t pos = line.find("username:");
            if (pos != string::npos)
            {
                size_t start = pos + 9;  // Skip past "username:"
                size_t end = line.find(",", start);
                string existing_username = line.substr(start, end - start);
                if (existing_username == username)
                {
                    return false;  // If username matches already existing usernames, return false
                }
            }
        }
        file.close();
    }
    return true; // Username is unique
}

// 4. Function to check if the email is unique by searching the creds.txt file
bool is_email_unique(const string& email)
{
    ifstream file("creds.txt");
    if (file.is_open())
    {
        string line;
        while (getline(file, line))
        {
            size_t pos = line.find("email:");
            if (pos != string::npos)
            {
                size_t start = pos + 6;  // Skip past "email:"
                size_t end = line.find(",", start);
                string existing_email = line.substr(start, end - start);
                if (existing_email == email)
                {
                    return false;  // If email matches already existing emails, return false
                }
            }
        }
        file.close();
    }
    return true; // Email is unique
}

// 5. Function to store user credentials in creds.txt
void store_credentials(const string& email, const string& username, const string& hashed_password, const string& salt)
{
    ofstream file("creds.txt", ios::app);
    if (file.is_open())
    {
        file << "email:" << email << ", username:" << username << ", password:" << hashed_password << ", salt:" << salt << endl;
        file.close();
    }
}

// 6. Function to validate the email format
bool is_valid_email(const string& email)
{
    const regex pattern(R"((\w+)@(gmail\.com|nu\.edu\.pk))"); // Simple regex for email validation
    return regex_match(email, pattern);
}

// 7. Function to validate email input from the client
void validate_email(int client_socket, string email)
{
    if (is_valid_email(email) && is_email_unique(email))
    {
        send(client_socket, "Email is valid and unique.", 30, 0);
    }
    else
    {
        send(client_socket, "Invalid or already registered email.", 40, 0);
    }
}

// 8. Function to validate username input from the client
void validate_username(int client_socket, string username)
{
    if (is_username_unique(username))
    {
        send(client_socket, "Username is unique.", 20, 0);
    }
    else
    {
        send(client_socket, "Username already exists.", 25, 0);
    }
}

// 9. Function to register the user
bool register_user(string email, string username, string password)
{
    // Generate salt and hash the password
    string salt = generate_salt();
    string hashed_password = hash_password(password, salt);
   
    // Store credentials
    store_credentials(email, username, hashed_password, salt);
    return true;
}

// 10. server side Function to login the user
bool login_user(int client_socket, unsigned char* aes_key)
{
    unsigned char buf[256];
    unsigned char decrypted_buf[256];
   
    // Receive IV
    unsigned char iv[AES_BLOCK_SIZE];
    int iv_len = recv(client_socket, iv, sizeof(iv), 0);
    if (iv_len <= 0)
    {
        cerr << "\033[1;31m Error receiving IV!\033[0m" << endl;
        return false;
    }

    // Username loop
    string username;
    bool usernameValid = false;
    while (!usernameValid)
    {
        // Receive length of encrypted username
        int username_len;
        int username_len_len = recv(client_socket, reinterpret_cast<char*>(&username_len), sizeof(username_len), 0);
        if (username_len_len <= 0)
        {
            cerr << "\033[1;31m Error receiving username length!\033[0m" << endl;
            return false;
        }

        // Receive encrypted username
        unsigned char encrypted_username[256];
        int username_len_recv = recv(client_socket, encrypted_username, username_len, 0);
        if (username_len_recv <= 0)
        {
            cerr << "\033[1;31m Error receiving username!\033[0m" << endl;
            return false;
        }

        // Decrypt username
        unsigned char decrypted_username[256];
        int decrypted_username_len = decrypt(encrypted_username, username_len, decrypted_username, aes_key, iv);
        if (decrypted_username_len < 0)
        {
            cerr << "Decryption failed!" << endl;
            return false;
        }
        decrypted_username[decrypted_username_len] = '\0'; // Null-terminate the string
        username = reinterpret_cast<char*>(decrypted_username);

        // Check if username exists
        ifstream file("creds.txt");
        if (file.is_open())
        {
            string line;
            bool found = false;
            while (getline(file, line))
            {
                size_t pos = line.find("username:");
                if (pos != string::npos)
                {
                    size_t start = pos + 9;  // Skip past "username:"
                    size_t end = line.find(",", start);
                    string existing_username = line.substr(start, end - start);
                   
                    if (existing_username == username)
                    {
                        found = true;
                        break;
                    }
                }
            }
            file.close();

            if (found)
            {
                cout << "\n\033[01;32m Username exists.\033[0m" << endl;
                send(client_socket, "Username exists.", 16, 0);
                usernameValid = true;
            }
            else
            {
                cout << "\n\033[01;31m Username does not exist.\033[0m" << endl;
                send(client_socket, "Username does not exist.", 25, 0);
            }
        }
        else
        {
            cout << "\n\033[1;31m Error opening creds.txt!\033[0m" << endl;
            return false;
        }
    }

    // Password loop
    string password;
    bool passwordValid = false;
    while (!passwordValid)
    {
        // Receive length of encrypted password
        int password_len;
        int password_len_len = recv(client_socket, reinterpret_cast<char*>(&password_len), sizeof(password_len), 0);
        if (password_len_len <= 0)
        {
            cerr << "\033[1;31m Error receiving password length!\033[0m" << endl;
            return false;
        }

        // Receive encrypted password
        unsigned char encrypted_password[256];
        int password_len_recv = recv(client_socket, encrypted_password, password_len, 0);
        if (password_len_recv <= 0)
        {
            cerr << "\033[1;31m Error receiving password!\033[0m" << endl;
            return false;
        }

        // Decrypt password
        unsigned char decrypted_password[256];
        int decrypted_password_len = decrypt(encrypted_password, password_len, decrypted_password, aes_key, iv);
        if (decrypted_password_len < 0)
        {
            cerr << "\033[1;31m Decryption failed!\033[0m" << endl;
            return false;
        }
        decrypted_password[decrypted_password_len] = '\0'; // Null-terminate the string
        password = reinterpret_cast<char*>(decrypted_password);

        // Check if password is correct
        ifstream file("creds.txt");
        if (file.is_open())
        {
            string line;
            bool found = false;
            while (getline(file, line))
            {
                size_t pos = line.find("username:");
                if (pos != string::npos)
                {
                    size_t start = pos + 9;  // Skip past "username:"
                    size_t end = line.find(",", start);
                    string existing_username = line.substr(start, end - start);
                   
                    if (existing_username == username)
                    {
                        size_t password_pos = line.find("password:");
                        size_t password_start = password_pos + 9; // Skip past "password:"
                        size_t password_end = line.find(",", password_start);
                        string existing_hashed_password = line.substr(password_start, password_end - password_start);
                       
                        // Hash the input password with the stored salt
                        size_t salt_pos = line.find("salt:");
                        size_t salt_start = salt_pos + 5; // Skip past "salt:"
                        string salt = line.substr(salt_start);
                        string hashed_input_password = hash_password(password, salt);
                       
                        if (hashed_input_password == existing_hashed_password)
                        {
                            cout << "\n\033[01;32m Password is correct.\033[0m" << endl;
                            send(client_socket, "Password is correct.", 20, 0);
                            passwordValid = true;
                        }
                        else
                        {
                            cout << "\n\033[01;31m Password is incorrect.\033[0m" << endl;
                            send(client_socket, "Password is incorrect.", 22, 0);
                        }
                        found = true;
                        break;
                    }
                }
            }
            file.close();

            if (!found)
            {
                cout << "\n\033[1;31m Error: username not found in creds.txt!\033[0m" << endl;
                return false;
            }
        }
        else
        {
            cout << "\n\033[1;31m Error opening creds.txt! \033[0m" << endl;
            return false;
        }
    }
   
    cout << "\n\t\033[01;35m Welcome " << username << " ! \033[0m" << endl;
    return true;
}

// server side Function to handle secure chat
void secure_chat(int client_socket, unsigned char* aes_key)
{
    cout << "\n\t\033[01;35m Start Your Conversation here! \033[0m" << endl;
    unsigned char buf[256];
    unsigned char decrypted_buf[256];
   
    while (true)
    {
        // Receive IV
        unsigned char iv[AES_BLOCK_SIZE];
        int iv_len = recv(client_socket, iv, sizeof(iv), 0);
        if (iv_len <= 0)
        {
            cout << "\033[1;31m Error receiving IV!\033[0m" << endl;
            break;
        }
       
        // Receive length of encrypted message
        int in_len;
        int in_len_len = recv(client_socket, &in_len, sizeof(in_len), 0);
        if (in_len_len <= 0)
        {
            cerr << "\033[1;31m Error receiving message length!\033[0m" << endl;
            break;
        }
       
        // Receive encrypted message
        unsigned char encrypted_message[256];
        int message_len_recv = recv(client_socket, encrypted_message, in_len, 0);
        if (message_len_recv <= 0)
        {
            cout << "\033[1;31m Error receiving message!\033[0m" << endl;
            break;
        }
       
        // Decrypt message
        int decrypted_len = decrypt(encrypted_message, in_len, decrypted_buf, aes_key, iv);
        if (decrypted_len < 0)
        {
            cout << "\033[1;31m Decryption failed!\033[0m" << endl;
            break;
        }
        decrypted_buf[decrypted_len] = '\0'; // Null-terminate the string
        string message((char*)decrypted_buf);
       
        if (message == "exit" || message == "bye")
        {
            // Encrypt response
            string response = "Exiting chat. Goodbye!";
            cout << "\033[1;35m Client has exited the chat! \033[0m" << endl;
            unsigned char encrypted_response[256];
            int out_len = encrypt((unsigned char*)response.c_str(), response.length(), encrypted_response, aes_key, iv);
           
            // Send IV followed by length and encrypted response
            send(client_socket, iv, sizeof(iv), 0); // Send IV first
            send(client_socket, &out_len, sizeof(out_len), 0); // Send length of encrypted response
            send(client_socket, encrypted_response, out_len, 0); // Send encrypted response
            break;
        }
       
        cout << "\n Client: " << message << endl;
       
        // Send response
        string response;
        cout << " Server: ";
        getline(cin, response);
       
        // Encrypt response
        unsigned char encrypted_response[256];
        int out_len = encrypt((unsigned char*)response.c_str(), response.length(), encrypted_response, aes_key, iv);
       
        // Send IV followed by length and encrypted response
        send(client_socket, iv, sizeof(iv), 0); // Send IV first
        send(client_socket, &out_len, sizeof(out_len), 0); // Send length of encrypted response
        send(client_socket, encrypted_response, out_len, 0); // Send encrypted response
    }
}

// Function to encrypt data using AES
int encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, const unsigned char *key, unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;
    // Initialize encryption
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);
    // Encrypt the data
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    // Finalize encryption (adds padding)
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;  // Return total length of ciphertext
}

// Function to decrypt data using AES
int decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, const unsigned char *key, const unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;
    // Initialize decryption
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    // Decrypt the data
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    // Finalize decryption (removes padding)
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0)
    {
        cerr << "Decryption finalization failed!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;  // Decryption failed
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;  // Return total length of plaintext
}
