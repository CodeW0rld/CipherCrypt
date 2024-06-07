# CipherCrypt
CipherCrypt is a Python application that allows users to encrypt and decrypt messages using the Caesar Cipher algorithm. The application provides a graphical user interface (GUI) built with the Tkinter library.

**Features**
+ Encrypt messages using a user-provided key (1-26)
+ Decrypt encrypted messages by entering the correct key
+ Save encrypted messages to files on the user's computer
+ Load and decrypt previously saved encrypted messages

**Requirements**
+ Python 3.x
+ Tkinter library (usually included with Python installations)

**Installation**
+ Clone the repository:
`git clone https://github.com/your-username/CipherCrypt.git`

+ Navigate to the project directory:
`cd CipherCrypt`

**Usage**
1. Run the CipherCrypGUI.py script to start the application:
`python CipherCrypGUI.py`

2. The main window will appear with three buttons: "Encrypt", "Decrypt", and "Exit".
3.To encrypt a message:
  + Click the "Encrypt" button.
  + Enter your user ID, a key (an integer between 1 and 26), and the message to be encrypted.
  + Click the "Encrypt" button within the encryption window.
  + The encrypted message will be saved to a file with the format <user_id>_message.txt in the same directory as the script.
  + You will be prompted to continue to the decryption window or exit the application.
    
4. To decrypt a message:
+ Click the "Decrypt" button in the main window.
+ Enter your user ID and the key used for encryption.
+ Click the "Decrypt" button within the decryption window.
+ If the correct key is provided, the decrypted message will be displayed in the text area.
+ If the key is incorrect, you will be given a limited number of attempts (3) before the application exits.

**Code Structure**

The application consists of three main classes:
  1. CaesarCipher: Handles the encryption and decryption of messages using the Caesar Cipher algorithm.
  2. FileManager: Manages the saving and loading of encrypted messages to/from files.
  3. CipherCrypGUI: Implements the graphical user interface and handles user interactions.

**License**

This project is licensed under the MIT License.

**Limitations**

This is a basic Caesar Cipher and has limitations:
+ It only encrypts alphabetical characters (a-z, A-Z).
Please be aware it's not the safest encryption method, as someone can easily crack the code by trying different key values (brute-force attack).
