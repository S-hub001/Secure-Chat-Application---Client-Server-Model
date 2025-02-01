#include <iostream>
#include <cmath>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <random>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <arpa/inet.h>

using namespace std;

// Diffie-Hellman parameters
const int prime = 23;  // A prime number
const int base = 5;    // A primitive root modulo prime

// AES parameters
const int AES_KEY_SIZE = 128; // AES key size in bits
const int MY_AES_BLOCK_SIZE = 16; // AES block size in bytes

// Function declarations
void display_menu();
void handle_login(int sock, unsigned char* aes_key);
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, const unsigned char *key, unsigned char *iv);
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, const unsigned char *key, const unsigned char *iv) ;
int modular_pow(int base, int exp, int mod);
void derive_aes_key(int shared_secret, unsigned char* aes_key);
void generate_random_iv(unsigned char* iv);
void secure_chat(int sock, unsigned char* aes_key) ;

int sock;

void create_socket()
{
    // Create the socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Setup an address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1"); // Use the correct server IP
    server_address.sin_port = htons(8080);
   
    // Connect to the server
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
    {
        perror("Error connecting to server");
        exit(EXIT_FAILURE);
    }
}

int generate_private_key()
{
    random_device rd;
    mt19937 eng(rd());
    uniform_int_distribution<> distr(1, prime - 1);
    return distr(eng);
}

int calculate_public_key(int private_key)
{
    return modular_pow(base, private_key, prime);
}

int compute_shared_secret(int public_key, int private_key)
{
    return modular_pow(public_key, private_key, prime);
}

int modular_pow(int base, int exp, int mod)
{
    int result = 1;
    base = base % mod;
    while (exp > 0)
    {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

void derive_aes_key(int shared_secret, unsigned char* aes_key)
{
    //unsigned char aes_key[16];
    for (int i= 0 ; i < 16 ; i++)
    {
       aes_key[i] = (shared_secret >> (8 * (15-i))) & 0xFF;  
    }
}

void generate_random_iv(unsigned char* iv)
{
    RAND_bytes(iv, 16);
}

int main()
{
    char buf[256];

    // Create socket and connect to the server
    create_socket();
   
    cout << "\n\n\033[1;4;34m\t >>>>>>>>>> XYZ University Chat Client <<<<<<<<<<\n\n\033[0m";
   
    // Diffie-Hellman Key Exchange
    int client_private_key = generate_private_key();
    int client_public_key = calculate_public_key(client_private_key);

    // Send client public key to server
    if (send(sock, &client_public_key, sizeof(client_public_key), 0) < 0)
    {
        perror("Error sending public key to server");
        exit(EXIT_FAILURE);
    }

    // Receive server public key
    int server_public_key;
    if (recv(sock, &server_public_key, sizeof(server_public_key), 0) <= 0)
    {
        perror("Error receiving server public key");
        exit(EXIT_FAILURE);
    }

    // Compute shared secret
    int shared_secret = compute_shared_secret(server_public_key, client_private_key);
    cout << "\n\033[1;33m Shared Secret (Client): " << shared_secret << "\033[0m" << endl;

    // Derive AES key from shared secret
    unsigned char aes_key[AES_KEY_SIZE / 8]; // 16 bytes for AES-128
    derive_aes_key(shared_secret, aes_key);
    // Print AES key
    cout << endl << "\033[1;33m AES_key (client): ";
    for (int i = 0; i < AES_KEY_SIZE / 8; i++)
    {
        cout << (int)aes_key[i] << " ";
    }
    cout << "\033[0m" << endl;

    int choice;
    char continue_choice = 'y';

    while (continue_choice == 'y' || continue_choice == 'Y')
    {
        display_menu();
        cin >> choice;
        cin.ignore();  // Ignore newline character left in buffer
       
        // Send the choice to the server
        string choice_str = to_string(choice);
        send(sock, choice_str.c_str(), choice_str.size() + 1, 0);  // +1 for null terminator

        if (choice == 3)
        {
            cout << "\n\033[1;31m You have exited the chat. Goodbye!\033[0m\n";
            close(sock);  // Close the socket before exiting
            exit(0);      // Properly terminate the program
        }

        // Client side registration case
        if (choice == 1)
        {
            string email, username, password;
            unsigned char iv[MY_AES_BLOCK_SIZE];
            generate_random_iv(iv); // Generate random IV for CBC mode
            // Send IV and encrypted email
            send(sock, iv, sizeof(iv), 0); // Send IV first

            bool emailValid = false;
            while (!emailValid)
            {
                // Collect email
                cout << "\n Enter a valid email address \033[1;33m(allowed: @gmail.com, @nu.edu.pk)\033[0m: ";
                getline(cin, email);

                // Encrypt email
                unsigned char encrypted_email[256];
                int email_out_len = aes_encrypt(reinterpret_cast<const unsigned char*>(email.c_str()), email.length(), encrypted_email, aes_key, iv);

                send(sock, &email_out_len, sizeof(email_out_len), 0); // Send length of encrypted email
                send(sock, encrypted_email, email_out_len, 0); // Send encrypted email

                // Receive response
                char email_response[256];
                int response_len = recv(sock, email_response, sizeof(email_response) - 1, 0);
                if (response_len > 0)
                {
                    email_response[response_len] = '\0'; // Null-terminate the response
                }
                else
                {
                    cout << "\n Error receiving email response!" << endl;
                    continue;
                }

                // Check if email is valid and unique
                if (string(email_response) == "Email is valid and unique.")
                {
                    emailValid = true;
                }
                else
                {
                    cout << "\n \033[1;31m" << email_response << "\033[0m " << endl;
                }
            }

            bool usernameValid = false;
            while (!usernameValid)
            {
                // Collect username
                cout << "\n Enter a unique username: ";
                getline(cin, username);

                // Encrypt username
                unsigned char encrypted_username[256];
                int username_out_len = aes_encrypt(reinterpret_cast<const unsigned char*>(username.c_str()), username.length(), encrypted_username, aes_key, iv);

                // Send length of encrypted username
                send(sock, &username_out_len, sizeof(username_out_len), 0);

                // Send encrypted username
                send(sock, encrypted_username, username_out_len, 0);

                // Receive response
                char username_response[256];
                int response_len = recv(sock, username_response, sizeof(username_response) - 1, 0);
                if (response_len > 0)
                {
                    username_response[response_len] = '\0'; // Null-terminate the response
                }
                else
                {
                    cout << "\n Error receiving username response!" << endl;
                    continue;
                }

                // Check if username is unique
                if (string(username_response) == "Username is unique.")
                {
                    usernameValid = true;
                }
                else
                {
                    cout << "\n \033[1;31m" << username_response << "\033[0m" << endl;
                }
            }

            // Collect password
            cout << "\n Enter your password: ";
            getline(cin, password);

            // Encrypt password
            unsigned char encrypted_password[256];
            int password_out_len = aes_encrypt(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), encrypted_password, aes_key, iv);

            // Send length of encrypted password
            send(sock, &password_out_len, sizeof(password_out_len), 0);

            // Send encrypted password
            send(sock, encrypted_password, password_out_len, 0);

            // Receive response
            char registration_response[256];
            int response_len = recv(sock, registration_response, sizeof(registration_response) - 1, 0);
            if (response_len > 0)
            {
                registration_response[response_len] = '\0'; // Null-terminate the response
            }
            else
            {
                cout << "Error receiving registration response!" << endl;
            }

            cout << "\n\033[1;32m " << registration_response << "\033[0m\n" << endl;
        }
       
        // client side login case
        if (choice == 2)
        {
            handle_login(sock, aes_key);
        }

        cout << "\n Would you like to perform another action? (y/n): ";
        cin >> continue_choice;
        cin.ignore();

        if (continue_choice == 'n' || continue_choice == 'N')
        {
            cout << "\n\033[1;31m You have exited the chat. Goodbye!\033[0m\n";
            break;
        }
    }

    close(sock);
    return 0;
}

void display_menu()
{
    cout << "\n\033[1;36m ==========================\033[0m" << endl;
    cout << "\033[1;35m        Chat Menu\033[0m" << endl;
    cout << "\033[1;36m ==========================\033[0m" << endl;
    cout << " 1. Register" << endl;
    cout << " 2. Login" << endl;
    cout << " 3. Exit: " << endl;
    cout << " =========================" << endl;
    cout << " Please choose an option (1-3): ";
}

// client side login handling
void handle_login(int sock, unsigned char* aes_key)
{
    string username, password;

    // Generate random IV
    unsigned char iv[MY_AES_BLOCK_SIZE];
    generate_random_iv(iv);

    // Send IV to server
    send(sock, iv, sizeof(iv), 0);

    bool usernameValid = false;
    while (!usernameValid)
    {
        cout << "\n Enter your username: ";
        getline(cin, username);

        // Encrypt username
        unsigned char encrypted_username[256];
        int username_out_len = aes_encrypt((unsigned char*)username.c_str(), username.length(), encrypted_username, aes_key, iv);

        // Send length of encrypted username
        send(sock, &username_out_len, sizeof(username_out_len), 0);

        // Send encrypted username
        send(sock, encrypted_username, username_out_len, 0);

        // Receive response from server
        char response[256];
        int response_len = recv(sock, response, sizeof(response), 0);
        if (response_len <= 0)
        {
            cerr << "\n \033[1;31m Error receiving response from server! \033[0m" << endl;
            return;
        }
        response[response_len] = '\0'; // Null-terminate the response
        string response_str(response);

        if (response_str == "Username exists.")
        {
            usernameValid = true;
        }
        else if (response_str == "Username does not exist.")
        {
            cout << "\n\t\033[1;31m " << response_str << "! \033[0m" << endl;
        }
        else
        {
            cout << "\033[1;31m Error: " << response_str << "\033[0m" << endl;
            return;
        }
    }

    bool passwordValid = false;
    while (!passwordValid)
    {
        cout << "\n Enter your password: ";
        getline(cin, password);

        // Encrypt password
        unsigned char encrypted_password[256];
        int password_out_len = aes_encrypt((unsigned char*)password.c_str(), password.length(), encrypted_password, aes_key, iv);

        // Send length of encrypted password
        send(sock, &password_out_len, sizeof(password_out_len), 0);

        // Send encrypted password
        send(sock, encrypted_password, password_out_len, 0);

        // Receive response from server
        char response[256];
        int response_len = recv(sock, response, sizeof(response), 0);
        if (response_len <= 0)
        {
            cerr << "\033[1;31m Error receiving response from server!\033[0m" << endl;
            return;
        }
        response[response_len] = '\0'; // Null-terminate the response
        string response_str(response);

        if (response_str == "Password is correct.")
        {
            passwordValid = true;
        }
        else if (response_str == "Password is incorrect.")
        {
            cout << "\n\t\033[1;31m " << response_str << "! \033[0m" << endl;
        }
        else
        {
            cout << "\033[1;31m Error: " << response_str << "! \033[0m " << endl;
            return;
        }
    }

    // Start secure chat
    secure_chat(sock, aes_key);
}

// client side Function to handle secure chat
void secure_chat(int sock, unsigned char* aes_key)
{
    cout << "\n\t\033[01;35m Start Your Conversation here! \033[0m" << endl;
    unsigned char buf[256];
    unsigned char decrypted_buf[256];
    unsigned char iv[MY_AES_BLOCK_SIZE];
   
    while (true)
    {
        // Send message
        string message;
        cout << "\n Client: ";
        getline(cin, message);

        if (message == "exit" || message == "bye")
        {
            // Encrypt message
            unsigned char encrypted_message[256];
            int out_len = aes_encrypt((unsigned char*)message.c_str(), message.length(), encrypted_message, aes_key, iv);

            // Send IV followed by length and encrypted message
            send(sock, iv, sizeof(iv), 0); // Send IV first
            send(sock, &out_len, sizeof(out_len), 0); // Send length of encrypted message
            send(sock, encrypted_message, out_len, 0); // Send encrypted message

            // Receive response
            unsigned char response_iv[AES_BLOCK_SIZE];
            int response_iv_len = recv(sock, response_iv, sizeof(response_iv), 0);
            if (response_iv_len <= 0)
            {
                cerr << "\033[1;31m Error receiving response IV! \033[0m" << endl;
                break;
            }
            unsigned char encrypted_response[256];
            int response_in_len;
            int response_in_len_len = recv(sock, &response_in_len, sizeof(response_in_len), 0);
            if (response_in_len_len <= 0)
            {
                cerr << "\033[1;31m Error receiving response length!\033[0m" << endl;
                break;
            }
            int response_len_recv = recv(sock, encrypted_response, response_in_len, 0);
            if (response_len_recv <= 0)
            {
                cerr << "\033[1;31m Error receiving response!\033[0m" << endl;
                break;
            }
            unsigned char decrypted_response[256];
            int decrypted_response_len = aes_decrypt(encrypted_response, response_in_len, decrypted_response, aes_key, response_iv);
            if (decrypted_response_len < 0)
            {
                cerr << "\033[1;31m Decryption failed!\033[0m" << endl;
                break;
            }
            decrypted_response[decrypted_response_len] = '\0'; // Null-terminate the string
            string response((char*)decrypted_response);

            cout << "\n\033[1;32m " << response << "\033[0m" << endl;
            break;
        }

        // Encrypt message
        unsigned char encrypted_message[256];
        int out_len = aes_encrypt((unsigned char*)message.c_str(), message.length(), encrypted_message, aes_key, iv);

        // Send IV followed by length and encrypted message
        send(sock, iv, sizeof(iv), 0); // Send IV first
        send(sock, &out_len, sizeof(out_len), 0); // Send length of encrypted message
        send(sock, encrypted_message, out_len, 0); // Send encrypted message

        // Receive response
        unsigned char response_iv[AES_BLOCK_SIZE];
        int response_iv_len = recv(sock, response_iv, sizeof(response_iv), 0);
        if (response_iv_len <= 0)
        {
            cerr << "\033[1;31m Error receiving response IV!\033[0m" << endl;
            break;
        }
        unsigned char encrypted_response[256];
        int response_in_len;
        int response_in_len_len = recv(sock, &response_in_len, sizeof(response_in_len), 0);
        if (response_in_len_len <= 0)
        {
            cerr << "\033[1;31m Error receiving response length!\033[0m" << endl;
            break;
        }
        int response_len_recv = recv(sock, encrypted_response, response_in_len, 0);
        if (response_len_recv <= 0)
        {
            cerr << "\033[1;31m Error receiving response!\033[0m" << endl;
            break;
        }
        unsigned char decrypted_response[256];
        int decrypted_response_len = aes_decrypt(encrypted_response, response_in_len, decrypted_response, aes_key, response_iv);
        if (decrypted_response_len < 0)
        {
            cerr << "\033[1;31m Decryption failed!\033[0m" << endl;
            break;
        }
        decrypted_response[decrypted_response_len] = '\0'; // Null-terminate the string
        string response((char*)decrypted_response);

        cout << " Server: " << response << endl;
    }
}

// Function to encrypt data using AES
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, const unsigned char *key, unsigned char *iv)
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
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, const unsigned char *key, const unsigned char *iv)
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
