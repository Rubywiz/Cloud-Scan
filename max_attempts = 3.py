max_attempts = 3
attempts = 0

while attempts <= max_attempts:
    username = input("Enter your username:")
    password = input("Enter your password")

if username == "admin" and password == "password123":
    print("Login Successful")
elif username != "admin" and password != "password123":
    print("Unsuccessful Login, try again.")
    print(f"You have {max_attempts - 1} attempts left.")

else:
    print("You have exceeded the maximum number of login attempts. ACCESS DENIED.")