import hashlib
import itertools
import math
import pandas as pd
import string
import matplotlib.pyplot as plt

# Sample dictionary wordlist for simulation 
dictionary = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome', 'abc123']

# Sample password dataset for analysis
sample_data = {
    'password': ['pass', 'Password1232', 'abc123', 'StrongPass2025!', 'weak'],
    'length': [4, 10, 6, 15, 4],
    'has_upper': [False, True, False, True, False],
    'has_lower': [True, True, True, True, True],
    'has_digit': [False, True, True, True, False],
    'has_special': [False, True, False, True, False]
}

def hash_password(password, algorithm='sha256'):
    """Hash a password using hashlib."""
    hasher = hashlib.new(algorithm)
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

def brute_force_sim(target_hash, max_length=4, charset=string.ascii_lowercase + string.digits):
    """Simulate brute-force attack (limited to avoid long runs)."""
    print("Simulating brute-force attack...")
    for length in range(1, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            attempt_str = ''.join(attempt)
            if hash_password(attempt_str) == target_hash:
                return attempt_str
    return None

def dictionary_attack_sim(target_hash):
    """Simulate dictionary attack."""
    print("Simulating dictionary attack...")
    for word in dictionary:
        if hash_password(word) == target_hash:
            return word
    return None

def calculate_entropy(password):
    """Calculate password entropy (strength measure)."""
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)
    if charset_size <= 0:
        return 0.0
    return len(password) * math.log2(charset_size)

def analyze_dataset():
    """Analyze sample passwords with Pandas and plot entropy."""
    df = pd.DataFrame(sample_data)
    df['entropy'] = df['password'].apply(calculate_entropy)
    df['strength'] = df['entropy'].apply(lambda e: 'Weak' if e < 30 else 'Medium' if e < 60 else 'Strong')
    print("\nPassword Dataset Analysis:")
    print(df)

    # Plot entropy
    ax = df['entropy'].plot(kind='bar', title='Password Entropy Analysis')
    ax.set_ylabel('Entropy (bits)')
    ax.set_xlabel('Password index')
    plt.tight_layout()
    plt.show()

    suggestions = [
        "Use at least 12 characters.",
        "Include uppercase, lowercase, digits, and special characters.",
        "Avoid common words; entropy should be >60 for strong passwords."
    ]
    return suggestions

def suggest_improvements(password, entropy):
    """Suggest password improvements."""
    suggestions = []
    if len(password) < 12:
        suggestions.append("Increase length to at least 12 characters.")
    if entropy < 60:
        suggestions.append("Add more variety: uppercase, digits, special chars.")
    return suggestions

def main():
    try:
        while True:
            print("\nPassword Cracker and Analyzer Menu:")
            print("1. Test a password (hash, crack sim, entropy, suggestions)")
            print("2. Analyze password dataset")
            print("3. Exit")
            choice = input("Enter choice: ").strip()
            
            if choice == '1':
                password = input("Enter password to test: ")
                hashed = hash_password(password)
                print(f"Hashed (SHA-256): {hashed}")
                
                # Simulate attacks (kept small for demo speed)
                cracked_bf = brute_force_sim(hashed, max_length=3)  # Limited to quick run
                cracked_dict = dictionary_attack_sim(hashed)
                if cracked_bf:
                    print(f"Cracked via brute-force: {cracked_bf}")
                elif cracked_dict:
                    print(f"Cracked via dictionary: {cracked_dict}")
                else:
                    print("Not cracked in simulation.")
                
                entropy = calculate_entropy(password)
                print(f"Entropy: {entropy:.2f} bits (Higher is stronger)")
                improvements = suggest_improvements(password, entropy)
                if improvements:
                    print("Suggestions:")
                    for s in improvements:
                        print(f"- {s}")
            
            elif choice == '2':
                suggestions = analyze_dataset()
                print("Secure Password Policies:")
                for s in suggestions:
                    print(f"- {s}")
            
            elif choice == '3':
                break
            else:
                print("Invalid choice.")
    except (KeyboardInterrupt, EOFError):
        print("\nExiting...")

if __name__ == "__main__":
    main()
