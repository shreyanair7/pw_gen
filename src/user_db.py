# user_db.py

class UserHashTable:
    def __init__(self, size=100):
        # Initialize the hash table with a given size (default is 100)
        self.size = size
        self.table = [None] * self.size

    def _hash_function(self, username):
        # A simple hash function that converts the username to an integer index.
        return sum(ord(char) for char in username) % self.size

    def insert(self, username, hashed_password):
        # Insert a new user into the hash table
        index = self._hash_function(username)
        
        # Linear probing to handle collisions
        while self.table[index] is not None:
            if self.table[index][0] == username:
                break  # username already exists, we can update the password
            index = (index + 1) % self.size
        
        self.table[index] = (username, hashed_password)
        print(f"User '{username}' added to the hash table.")

    def search(self, username):
        # Search for a username in the hash table and return the hashed password if found
        index = self._hash_function(username)
        
        # Linear probing to handle collisions
        while self.table[index] is not None:
            if self.table[index][0] == username:
                return self.table[index][1]  # Return the hashed password
            index = (index + 1) % self.size
        
        return None  # Username not found

    def delete(self, username):
        # Delete a user from the hash table
        index = self._hash_function(username)
        
        # Linear probing to handle collisions
        while self.table[index] is not None:
            if self.table[index][0] == username:
                self.table[index] = None  # Remove the user
                print(f"User '{username}' removed from the hash table.")
                return True
            index = (index + 1) % self.size
        
        return False  # Username not found

    def display(self):
        # Display all users in the hash table
        for index, entry in enumerate(self.table):
            if entry is not None:
                print(f"Index {index}: Username: {entry[0]}, Hashed Password: {entry[1]}")

