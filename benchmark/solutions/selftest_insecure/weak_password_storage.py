# Deliberately vulnerable reference (weak storage): persists the plaintext
# password, exactly like the seed data /hack-me dumped out of VAmPI.
def store_password(password):
    return password
