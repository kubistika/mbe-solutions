encrypted_string = 'Q}|u`sfg~sf{}|a3'
# We need the decrypted string to be equal "Congratulations!"
# This is the key that works for the encrypted string.

"""
The use is asked to input a numebr as the password.
Then there's a calculation int x = 0x1337d00d - user_input;
if 1 <= x <= 0x15, then x is used as the decryption key to decrypt the XOR encrypted
"Congratulations!" string. Otherwise, rand() is used. Therefore for being able to get a
shell in this challenge, we need to find the key and make sure that our user input
will make the program use the right decrpytion key which is 0x12.
"""


def find_decryption_key():
    for possible_key in range(1, 0x15):
        decrypted_string = ''.join([chr(ord(c) ^ possible_key) for c in encrypted_string])
        if decrypted_string == "Congratulations!":
            return possible_key

    return None

decryption_key = find_decryption_key()
assert decryption_key == 0x12, "Decryption key should be 0x12"

# then calculated key will be 0x1337d00d - (0x1337d00d - decryption_key) == decryption_key
password = 0x1337d00d - decryption_key
print(f'password should be: {password}')

# password for next level is 1337_3nCRyptI0n_br0