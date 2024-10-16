username = 'kubistika'

# some logic that calculates serial number based on the username
def calculate_serial(username: str) -> int:
    serial = (ord(username[3]) ^ 0x1337) + 0x5eeded
    for c in username:
        serial = serial + (ord(c) ^ serial) % 0x539
    return serial

print(calculate_serial(username))
