import math

# 1. Функция быстрого возведения числа в степень по модулю
def mod_exp(base, exp, mod):
    """
    Быстрое возведение base в степень exp по модулю mod.
    Возвращает (base ** exp) % mod
    """
    result = 1
    base = base % mod
    while exp > 0:
        # Если exp нечетное, умножаем результат на base
        if exp % 2 == 1:
            result = (result * base) % mod
        # Теперь exp делится на 2
        exp = exp >> 1
        base = (base * base) % mod
    return result

# 2. Функция расширенного алгоритма Евклида
def extended_gcd(a, b):
    """
    Реализует расширенный алгоритм Евклида.
    Возвращает тройку (gcd, x, y), где gcd - наибольший общий делитель
    чисел a и b, и x, y - коэффициенты такие, что a * x + b * y = gcd.
    """
    if a == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

# 3. Функция построения общего ключа по схеме Диффи-Хеллмана
def diffie_hellman(p, g, private_key_a, private_key_b):
    """
    Построение общего ключа по схеме Диффи-Хеллмана.
    p - большое простое число
    g - основание (первообразный корень)
    private_key_a - приватный ключ абонента A
    private_key_b - приватный ключ абонента B
    Возвращает общий секретный ключ.
    """
    # Публичный ключ абонента A: A = g^private_key_a % p
    A = mod_exp(g, private_key_a, p)
    # Публичный ключ абонента B: B = g^private_key_b % p
    B = mod_exp(g, private_key_b, p)
    
    # Общий ключ, который вычисляет абонент A: K_a = B^private_key_a % p
    shared_key_a = mod_exp(B, private_key_a, p)
    # Общий ключ, который вычисляет абонент B: K_b = A^private_key_b % p
    shared_key_b = mod_exp(A, private_key_b, p)
    
    # Оба должны получить один и тот же ключ
    assert shared_key_a == shared_key_b
    return shared_key_a

# 4. Функция нахождения дискретного логарифма (алгоритм Шаг младенца, шаг великана)
def brute_force_discrete_log(g, h, p):
    """
    Решает дискретный логарифм полным перебором.
    Ищет такое x, что g^x ≡ h (mod p) за O(p*log(p)).
    """
    for x in range(p):
        if mod_exp(g, x, p) == h:
            return x
    return None

# Вспомогательная функция для шифрования файла
def encrypt_file(file_path, key, mod):
    """
    Шифрует файл с помощью ключа и модуля, используя простое побитовое XOR шифрование.
    file_path - путь к файлу для шифрования
    key - ключ для шифрования
    mod - модуль
    """
    with open(file_path, "rb") as file:
        data = file.read()
    
    encrypted_data = bytearray()
    for byte in data:
        encrypted_byte = (byte ^ (key % 256)) % mod
        encrypted_data.append(encrypted_byte)
    
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as enc_file:
        enc_file.write(encrypted_data)
    
    return encrypted_file_path

# Вспомогательная функция для расшифровки файла
def decrypt_file(encrypted_file_path, key, mod):
    """
    Расшифровывает файл с помощью ключа и модуля, используя простое побитовое XOR шифрование.
    encrypted_file_path - путь к зашифрованному файлу
    key - ключ для расшифровки
    mod - модуль
    """
    with open(encrypted_file_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
    
    decrypted_data = bytearray()
    for byte in encrypted_data:
        decrypted_byte = (byte ^ (key % 256)) % mod
        decrypted_data.append(decrypted_byte)
    
    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(decrypted_file_path, "wb") as dec_file:
        dec_file.write(decrypted_data)
    
    return decrypted_file_path
