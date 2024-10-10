# test_cryptolib.py

import unittest
import os
from cryptolib import mod_exp, extended_gcd, diffie_hellman, brute_force_discrete_log, encrypt_file, decrypt_file

class TestCryptoLib(unittest.TestCase):

    # Тест для mod_exp
    def test_mod_exp(self):
        self.assertEqual(mod_exp(2, 10, 1000), 24)  # 2^10 % 1000 = 24
        self.assertEqual(mod_exp(3, 13, 50), 23)    # 3^13 % 50 = 47
        self.assertEqual(mod_exp(10, 0, 7), 1)      # Любое число в степени 0 равно 1
    
    # Тест для extended_gcd
    def test_extended_gcd(self):
        gcd, x, y = extended_gcd(30, 50)
        self.assertEqual(gcd, 10)
        self.assertEqual(30 * x + 50 * y, 10)  # Проверка a * x + b * y = gcd(a, b)

        gcd, x, y = extended_gcd(101, 103)
        self.assertEqual(gcd, 1)
        self.assertEqual(101 * x + 103 * y, 1)  # Проверка для взаимно простых чисел
    
    # Тест для diffie_hellman
    def test_diffie_hellman(self):
        p = 23  # Простое число
        g = 5   # Основание
        private_key_a = 6
        private_key_b = 15
        shared_key = diffie_hellman(p, g, private_key_a, private_key_b)
        self.assertEqual(shared_key, 2)  # Ожидаемый общий ключ для этого набора параметров
    
    # Тест для brute_force_discrete_log
    def test_brute_force_discrete_log(self):
        g = 2  # Основание
        h = 5  # Искомое значение
        p = 11 # Простое число
        x = brute_force_discrete_log(g, h, p)
        self.assertEqual(x, 4)  # 2^4 % 11 = 5

    # Тесты для шифрования и дешифрования файлов
    def test_encrypt_decrypt_file(self):
        # Создаем тестовый файл
        test_file_path = "test_file.txt"
        with open(test_file_path, "w") as test_file:
            test_file.write("Это тестовый файл")

        # Шифруем файл
        key = 123456
        mod = 256
        encrypted_file_path = encrypt_file(test_file_path, key, mod)
        self.assertTrue(os.path.exists(encrypted_file_path))

        # Расшифровываем файл
        decrypted_file_path = decrypt_file(encrypted_file_path, key, mod)
        self.assertTrue(os.path.exists(decrypted_file_path))

        # Сравниваем содержимое исходного и расшифрованного файла
        with open(test_file_path, "r") as original_file:
            original_data = original_file.read()
        
        with open(decrypted_file_path, "r") as decrypted_file:
            decrypted_data = decrypted_file.read()
        
        self.assertEqual(original_data, decrypted_data)

        # Удаляем тестовые файлы после тестирования
        os.remove(test_file_path)
        os.remove(encrypted_file_path)
        os.remove(decrypted_file_path)

if __name__ == '__main__':
    unittest.main()
