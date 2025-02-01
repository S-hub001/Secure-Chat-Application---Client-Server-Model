# 🔐 Secure-Chat-Application---Client-Server-Model

This project is a basic implementation of a **secure chat application** using the **client-server model**. The application allows users to **register, log in, and chat securely** with encrypted communication.  
It uses **Diffie-Hellman key exchange** for key agreement and **AES-128 encryption** for message confidentiality.

---

## 🚀 Features

### ✅ User Registration and Login
- Users can **register** with a unique **username, email, and password**.
- Registered users can **log in** to start a secure chat session.

### 🔒 Secure Communication
- **Diffie-Hellman Key Exchange**: Establishes a shared secret between the client and server.
- **AES-128 Encryption**: Encrypts all messages exchanged between the client and server using **CBC mode**.

### 💬 Basic Chat Functionality
- Users can **send and receive encrypted messages** in real-time.
- The chat session can be **terminated** by typing `exit` or `bye`.

---

## 🛠️ How It Works

### 1️⃣ Key Exchange (Diffie-Hellman)
1. The client and server agree on a **prime number** and a **base** (primitive root modulo prime).
2. Each party generates a **private key** and computes a **public key**.
3. Public keys are exchanged, and both parties compute a **shared secret**.
4. The shared secret is used to derive an **AES encryption key**.

### 2️⃣ Encryption (AES-128)
- All messages (including **login credentials and chat messages**) are encrypted using **AES-128 in CBC mode**.
- A random **Initialization Vector (IV)** is generated for each message to ensure **uniqueness**.

### 3️⃣ Client-Server Communication
- The **client connects** to the server and **performs the key exchange**.
- The client can **register, log in, and start a secure chat session**.
- Messages are **encrypted before being sent** and **decrypted upon receipt**.

---

## 📜 Code Overview

### **📌 Client Code (`client.cpp`)**
- **Socket Creation**: Establishes a **connection** to the server.
- **Key Exchange**: Implements the **Diffie-Hellman key exchange protocol**.
- **AES Encryption/Decryption**: Handles **encryption and decryption** of messages.
- **User Interaction**: Provides a **menu for registration, login, and chat**.

### **📌 Server Code (`server.cpp`)**
- **Socket Creation**: Listens for **incoming client connections**.
- **Key Exchange**: Implements the **Diffie-Hellman key exchange protocol**.
- **AES Encryption/Decryption**: Handles **encryption and decryption** of messages.
- **User Authentication**: Manages **user registration and login**.
- **Secure Chat**: Facilitates **encrypted chat sessions** between the client and server.

---

## ⚙️ Prerequisites

Ensure you have the following installed before running the application:
- **OpenSSL**: For cryptographic functions (AES, SHA, etc.).
- **C++ Compiler**: Supports **C++11** or later.

---

## 🔧 Compilation and Execution

### **🔹 Compile the Server:**
g++ server.cpp -o s -lssl -lcrypto
### **🔹 Compile the Client:**
g++ client.cpp -o c -lssl -lcrypto

### ** Execute: **
**./s** -> for server.cpp on one terminal
**./c** -> for client.cpp on another terminal
