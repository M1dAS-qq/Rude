# rude v42
import os, sys, re, time, base64, zlib
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

errors = []

class NonCriticalError(Exception):
    pass

def get_text(key, default=None):
    """Безопасное получение текста по ключу"""
    lang_texts = TEXTS.get(LANG, TEXTS["en"])
    return lang_texts.get(key, default if default is not None else f"[MISSING: {key}]")

TEXTS = {
    "ru": {
        "banner": "rude - v42\n",
        "cmd": "Введите команду",
        "encrypt_mode": "Режим шифрования.",
        "decrypt_mode": "Режим дешифровки.",
        "enter_text": "Введите текст (до 4000 символов): ",
        "cipher": "Шифр:",
        "key": "Ключ:",
        "enter_cipher": "Введите шифр: ",
        "enter_key": "Введите ключ: ",
        "no_data": "Нет данных для обработки.",
        "processing": "Обработка...",
        "recovered": "Восстановленный текст:",
        "time": "Общее время:",
        "settings": "\nНастройки:",
        "updated": "Настройки обновлены.",
        "help": "\nКоманды:\n%mode1 [текст] - шифрование\n%mode2 [шифр] [ключ] - дешифровка\n%settings [параметры] - настройки\n%help [команда] - помощь\n%exit - выход\n",
        "idk": "Неизвестная команда. Используйте %help для справки",
        "help_mode1": "\n%mode1 [текст] - шифрование текста\n  [текст] - текст для шифрования (опционально)",
        "help_mode2": "\n%mode2 [шифр] [ключ] - дешифровка текста\n  [шифр] - зашифрованные данные\n  [ключ] - ключ для дешифровки",
        "help_settings": "\n%settings [параметры] - настройки программы\n  [параметры] - настройки в формате 'номер%значение'",
        "help_help": "\n%help [команда] - справка по командам\n  [команда] - имя команды без знака %",
        "help_exit": "\n%exit - выход из программы",
        "invalid_args": "Неверные аргументы. Воспользуйтесь командой \"%help [{}]\".",
        "invalid_args_count": "Неверное количество аргументов. Ожидается {}. Воспользуйтесь командой \"%help [{}]\".",
        "prompt_set": "Введите изменение (n%значение) или Enter для выхода: ",
        "goodbye": "Программа завершена. До свидания!",
        "key_info": "Информация из ключа:",
        "text_length": "Длина текста:",
        "timestamp": "Время создания:",
        "version": "Версия:",
        "control_flags": "Флаги:",
        "hpc_seed": "Сид HPC:",
        "local_identifier": "Локальный ID:",
        "algorithm": "Алгоритм:",
        "compression": "Сжатие:",
        "debug_mode": "Режим отладки:",
        "debug_on": "вкл",
        "debug_off": "выкл",
        "debug_random": "случайный",
        "warning_text_too_long": "Предупреждение: текст обрезан до 4000 символов",
        "warning_version_mismatch": "Внимание: версия ключа {} не совпадает с ожидаемой 42",
        "warning_length_mismatch": "Внимание: длина восстановленного текста ({}) не совпадает с ожидаемой ({})",
        "warning_crc_mismatch": "Внимание: контрольная сумма не совпадает - возможна ошибка в данных",
        "threads": "Потоки:",
        "hide_key_mode": "Скрытие ключа:",
        "hide_on": "вкл",
        "hide_off": "выкл",
        "enter_cipher_hidden": "Введите шифр (1 строка): ",
        "enter_key_hidden": "Введите ключ (2 строка): ",
        "error_invalid_char": "Ошибка: обнаружен недопустимый символ &",
        "error_crc_mismatch": "Ошибка: контрольная сумма не совпадает - данные повреждены",
        "error_encoding": "Ошибка: проблема с кодировкой ввода",
        "debug_key_derivation": "Вычисление ключа: CRC32={}",
        "debug_bytes_conversion": "Преобразование: {} символов -> {} байт",
        "debug_final_result": "Результат: {} -> {}",
        "debug_crc_check": "Проверка CRC: ожидается {}, получено {}",
        "debug_char_replaced": "Заменен символ: '{}' -> '{}'",
        "debug_char_removed": "Удален символ: '{}'",
        "algorithm_ctr": "AES-256-CTR",
        "algorithm_gcm": "AES-256-GCM",
        "algorithm_cbc": "AES-256-CBC",
        "algorithm_unknown": "Неизвестный алгоритм",
        "compression_none": "нет",
        "compression_fast": "быстрое",
        "compression_optimal": "оптимальное",
        "compression_max": "максимальное",
        "alphabet_auto": "авто",
        "alphabet_universal": "универсальный",
        "alphabet_russian": "русский",
        "alphabet_english": "английский",
        "alphabet_mode": "Режим алфавита:",
        "data_crc32": "Контрольная сумма:"
    },
    "en": {
        "banner": "rude - v42\n",
        "cmd": "Enter command",
        "encrypt_mode": "Encryption mode.",
        "decrypt_mode": "Decrypt mode.",
        "enter_text": "Enter text (up to 4000 chars): ",
        "cipher": "Cipher:",
        "key": "Key:",
        "enter_cipher": "Enter cipher: ",
        "enter_key": "Enter key: ",
        "no_data": "No data to process.",
        "processing": "Processing...",
        "recovered": "Recovered text:",
        "time": "Total time:",
        "settings": "\nSettings:",
        "updated": "Settings updated.",
        "help": "\nCommands:\n%mode1 [text] - encrypt\n%mode2 [cipher] [key] - decrypt\n%settings [parameters] - settings\n%help [command] - help\n%exit - exit\n",
        "idk": "Unknown command. Use %help for help",
        "help_mode1": "\n%mode1 [text] - encrypt text\n  [text] - text to encrypt (optional)",
        "help_mode2": "\n%mode2 [cipher] [key] - decrypt text\n  [cipher] - encrypted data\n  [key] - decryption key",
        "help_settings": "\n%settings [parameters] - program settings\n  [parameters] - settings in format 'number%value'",
        "help_help": "\n%help [command] - command help\n  [command] - command name without % sign",
        "help_exit": "\n%exit - exit program",
        "invalid_args": "Invalid arguments. Use command \"%help [{}]\".",
        "invalid_args_count": "Invalid arguments count. Expected {}. Use command \"%help [{}]\".",
        "prompt_set": "Enter change (n%value) or Enter to exit: ",
        "goodbye": "Program terminated. Goodbye!",
        "key_info": "Key information:",
        "text_length": "Text length:",
        "timestamp": "Creation time:",
        "version": "Version:",
        "control_flags": "Control flags:",
        "hpc_seed": "HPC seed:",
        "local_identifier": "Local ID:",
        "algorithm": "Algorithm:",
        "compression": "Compression:",
        "debug_mode": "Debug mode:",
        "debug_on": "on",
        "debug_off": "off",
        "debug_random": "random",
        "warning_text_too_long": "Warning: text truncated to 4000 characters",
        "warning_version_mismatch": "Warning: key version {} doesn't match expected 42",
        "warning_length_mismatch": "Warning: recovered text length ({}) doesn't match expected ({})",
        "warning_crc_mismatch": "Warning: CRC checksum mismatch - possible data corruption",
        "threads": "Threads:",
        "hide_key_mode": "Hide key:",
        "hide_on": "on",
        "hide_off": "off",
        "enter_cipher_hidden": "Enter cipher (line 1): ",
        "enter_key_hidden": "Enter key (line 2): ",
        "error_invalid_char": "Error: invalid character & detected",
        "error_crc_mismatch": "Error: CRC checksum mismatch - data corrupted",
        "error_encoding": "Error: input encoding problem",
        "debug_key_derivation": "Key derivation: CRC32={}",
        "debug_bytes_conversion": "Conversion: {} chars -> {} bytes",
        "debug_final_result": "Result: {} -> {}",
        "debug_crc_check": "CRC check: expected {}, got {}",
        "debug_char_replaced": "Character replaced: '{}' -> '{}'",
        "debug_char_removed": "Character removed: '{}'",
        "algorithm_ctr": "AES-256-CTR",
        "algorithm_gcm": "AES-256-GCM",
        "algorithm_cbc": "AES-256-CBC",
        "algorithm_unknown": "Unknown algorithm",
        "compression_none": "none",
        "compression_fast": "fast",
        "compression_optimal": "optimal",
        "compression_max": "maximum",
        "alphabet_auto": "auto",
        "alphabet_universal": "universal",
        "alphabet_russian": "russian",
        "alphabet_english": "english",
        "alphabet_mode": "Alphabet mode:",
        "data_crc32": "Data CRC32:"
    }
}

ERROR_TEXTS = {
    "ru": {
        "A1": "недопустимый символ",
        "A2": "текст превышает максимальную длину",
        "A3": "ошибка кодировки ввода",
        "B1": "некорректный формат шифра",
        "B2": "некорректный формат ключа",
        "C1": "общая ошибка шифрования",
        "D1": "ошибка расшифровки данных",
        "E1": "ошибка контрольной суммы",
        "F1": "некорректная настройка",
        "UNKNOWN": "неизвестная ошибка",
        "RETRY": "Повторите ввод."
    },
    "en": {
        "A1": "invalid character",
        "A2": "text exceeds maximum length",
        "A3": "input encoding error",
        "B1": "invalid cipher format",
        "B2": "invalid key format",
        "C1": "general encryption error",
        "D1": "data decryption error",
        "E1": "CRC checksum error",
        "F1": "invalid setting",
        "UNKNOWN": "unknown error",
        "RETRY": "Please retry input."
    }
}

LANG = "ru"

# Три оптимизированных алфавита для улучшения сжатия
ALPHABETS = {
    0: " оеаинтсрвлкмдупяыьгзбчйхжшюцщэфъёetaoinshrdlcumwfgypbvkjxqzABCDEFGHIJKLMNOPQRSTUVWXYZАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ0123456789_.,-–+?!%:;()[]{}\"'@#$/\\%^&*=_~|<>",  # Универсальный
    1: " оеаинтсрвлкмдупяыьгзбчйхжшюцщэфъёabcdefghijklmnopqrstuvwxyzАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.,-–+?!%:;()[]{}\"'@#$/\\%^&*=_~|<>",  # Русский
    2: " etaoinshrdlcumwfgypbvkjxqzабвгдеёжзийклмнопрстуфхцчшщъыьэюяABCDEFGHIJKLMNOPQRSTUVWXYZАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ0123456789_.,-–+?!%:;()[]{}\"'@#$/\\%^&*=_~|<>"   # Английский
}

# Глобальные переменные для текущего алфавита
CURRENT_ALPHABET = 0
CHAR_TO_BYTE = {}
BYTE_TO_CHAR = {}

def initialize_alphabet(alphabet_id):
    """Инициализирует выбранный алфавит"""
    global CURRENT_ALPHABET, CHAR_TO_BYTE, BYTE_TO_CHAR
    
    CURRENT_ALPHABET = alphabet_id
    chars = ALPHABETS[alphabet_id]
    
    CHAR_TO_BYTE = {char: i for i, char in enumerate(chars)}
    BYTE_TO_CHAR = {i: char for i, char in enumerate(chars)}
    BYTE_TO_CHAR[0xFF] = '&'  # Зарезервированный символ

# Инициализируем алфавит по умолчанию
initialize_alphabet(0)

# Настройки по умолчанию
SETTINGS = {
    "debug": False, 
    "hide_key": False, 
    "control_flags": None, 
    "threads": 4,
    "algorithm": 0,  # 0=CTR, 1=GCM, 2=CBC
    "compression": 0,  # 0=нет, 1=быстрое, 2=оптимальное, 3=максимальное
    "alphabet_mode": 0  # 0=авто, 1=универсальный, 2=русский, 3=английский
}

PROGRAM_VERSION = 42
MAX_TEXT_LENGTH = 4000

def safe_input(prompt):
    """Безопасный ввод с использованием системы ошибок"""
    while True:
        try:
            user_input = input(prompt)
            # Проверяем кодировку
            try:
                user_input.encode('utf-8')
                return user_input
            except UnicodeEncodeError as e:
                if SETTINGS['debug']:
                    print(f"[DEBUG] Ошибка кодировки UTF-8: {e}")
                error("A3")  # Ошибка кодировки ввода
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            if SETTINGS['debug']:
                print(f"[DEBUG] Ошибка кодировки ввода: {e}")
            error("A3")  # Ошибка кодировки ввода
        except EOFError:
            print("\n" + get_text("goodbye", "Программа завершена. До свидания!"))
            raise KeyboardInterrupt
        except Exception as e:
            errors.append(str(e))
            error("UNKNOWN")

def replace_missing_char(char):
    """Заменяет отсутствующий символ на ближайший аналог"""
    replacements = {
        '©': '(c)', '®': '(r)', '™': '(tm)',
        '€': 'EUR', '£': 'GBP', '¥': 'JPY',
        '—': '-', '–': '-', '«': '"', '»': '"',
        '„': '"', '“': '"', '‟': '"', '‹': "'", '›': "'",
        '¡': '!', '¿': '?', '°': 'deg', '±': '+/-', '×': 'x', '÷': '/',
        '¼': '1/4', '½': '1/2', '¾': '3/4', '√': 'sqrt', '∞': 'inf',
        '≠': '!=', '≤': '<=', '≥': '>=', '≈': '~', '≡': '=='
    }
    return replacements.get(char, None)

def normalize_text(text):
    """Преобразует текст к символам текущего алфавита"""
    result = []
    replacements_made = 0
    
    for char in text:
        if char in CHAR_TO_BYTE:
            result.append(char)
        else:
            # Заменяем отсутствующие символы на ближайшие аналоги
            replacement = replace_missing_char(char)
            if replacement:
                result.append(replacement)
                replacements_made += 1
                if SETTINGS['debug']:
                    debug_msg = get_text('debug_char_replaced', "Заменен символ: '{}' -> '{}'").format(char, replacement)
                    print(f"[DEBUG] {debug_msg}")
            else:
                # Если замена невозможна, используем пробел
                result.append(' ')
                replacements_made += 1
                if SETTINGS['debug']:
                    debug_msg = get_text('debug_char_removed', "Удален символ: '{}'").format(char)
                    print(f"[DEBUG] {debug_msg}")
    
    if replacements_made > 0 and SETTINGS['debug']:
        print(f"[DEBUG] Всего заменено символов: {replacements_made}")
    
    return ''.join(result)

def detect_language(text):
    """Автоматически определяет язык текста с улучшенной логикой"""
    ru_chars = set("абвгдеёжзийклмнопрстуфхцчшщъыьэюя")
    en_chars = set("abcdefghijklmnopqrstuvwxyz")
    
    ru_count = sum(1 for char in text.lower() if char in ru_chars)
    en_count = sum(1 for char in text.lower() if char in en_chars)
    other_count = len(text) - ru_count - en_count
    
    # Если текст состоит в основном из специальных символов/цифр
    if other_count > len(text) * 0.7:
        return 0  # Универсальный алфавит
    
    if ru_count > en_count * 1.5:
        return 1  # Русский
    elif en_count > ru_count * 1.5:
        return 2  # Английский
    else:
        return 0  # Универсальный

def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def compress_data(data, level):
    """Сжатие данных с указанным уровнем"""
    if level == 0:
        return data  # без сжатия
    return zlib.compress(data, level)

def decompress_data(data):
    """Распаковка данных"""
    try:
        return zlib.decompress(data)
    except:
        return data  # если не сжато, возвращаем как есть

def aes_ctr_cryptography(data, key):
    """Шифрование AES-256-CTR"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return nonce + encryptor.update(data) + encryptor.finalize()

def aes_ctr_decrypt_cryptography(encrypted_data, key):
    """Дешифрование AES-256-CTR"""
    if len(encrypted_data) < 16:
        raise ValueError("Данные слишком короткие для дешифровки")
    nonce, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def aes_gcm_encrypt(data, key):
    """Шифрование AES-256-GCM"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce + ciphertext + encryptor.tag

def aes_gcm_decrypt(encrypted_data, key):
    """Дешифрование AES-256-GCM"""
    if len(encrypted_data) < 28:  # 12 nonce + 16 tag
        raise ValueError("Данные слишком короткие для дешифровки")
    nonce, ciphertext, tag = encrypted_data[:12], encrypted_data[12:-16], encrypted_data[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def aes_cbc_encrypt(data, key):
    """Шифрование AES-256-CBC"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    # Добавляем padding для выравнивания до 16 байт
    pad_length = 16 - (len(data) % 16)
    data += bytes([pad_length] * pad_length)
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def aes_cbc_decrypt(encrypted_data, key):
    """Дешифрование AES-256-CBC"""
    if len(encrypted_data) < 32:  # 16 IV + минимум 16 данных
        raise ValueError("Данные слишком короткие для дешифровки")
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Удаляем padding
    pad_length = decrypted[-1]
    if pad_length > 16:
        raise ValueError("Неверный padding")
    return decrypted[:-pad_length]

def encrypt_data(data, key, algorithm):
    """Шифрование данных с выбранным алгоритмом"""
    if algorithm == 0:  # CTR
        return aes_ctr_cryptography(data, key)
    elif algorithm == 1:  # GCM
        return aes_gcm_encrypt(data, key)
    elif algorithm == 2:  # CBC
        return aes_cbc_encrypt(data, key)
    else:
        raise ValueError("Неизвестный алгоритм шифрования")

def decrypt_data(encrypted_data, key, algorithm):
    """Дешифрование данных с выбранным алгоритмом"""
    if algorithm == 0:  # CTR
        return aes_ctr_decrypt_cryptography(encrypted_data, key)
    elif algorithm == 1:  # GCM
        return aes_gcm_decrypt(encrypted_data, key)
    elif algorithm == 2:  # CBC
        return aes_cbc_decrypt(encrypted_data, key)
    else:
        raise ValueError("Неизвестный алгоритм шифрования")

def text_to_bytes(text):
    return bytes(CHAR_TO_BYTE[char] for char in text)

def bytes_to_text(data):
    result = []
    for byte in data:
        if byte == 0xFF:
            if SETTINGS['debug']:
                print(f"[DEBUG] Обнаружен зарезервированный байт: {byte:02X}")
            error("error_invalid_char")
        if byte not in BYTE_TO_CHAR:
            if SETTINGS['debug']:
                print(f"[DEBUG] Неизвестный байт: {byte:02X}")
            error("error_invalid_char")
        result.append(BYTE_TO_CHAR[byte])
    return ''.join(result)

def error(code):
    lang_texts = ERROR_TEXTS.get(LANG, ERROR_TEXTS["en"])
    msg = lang_texts.get(code, lang_texts["UNKNOWN"])
    
    if code in ("C1", "D1", "E1"):
        for e in errors:
            print(e)
        print(msg.upper())
        sys.exit(1)
    else:
        errors.append(msg.lower())
        print(f"{msg.lower()}\n{lang_texts['RETRY']}")
        raise NonCriticalError(code)

def apply_setting_direct(arg):
    global LANG
    m = re.match(r'(\d+)%(.+)$', arg)
    if not m: 
        return False
    
    n, v = int(m.group(1)), m.group(2)
    
    if n == 1:
        if v.lower() in ("on", "1"):
            SETTINGS['debug'] = True
            return True
        elif v.lower() in ("off", "0"):
            SETTINGS['debug'] = False
            return True
    
    elif n == 2:
        if v.lower() in ("on", "1"):
            SETTINGS['hide_key'] = True
            return True
        elif v.lower() in ("off", "0"):
            SETTINGS['hide_key'] = False
            return True
    
    elif n == 3:
        if v.lower() in ("ru", "en"):
            LANG = v.lower()
            return True
    
    elif n == 4:
        if v.lower() in ("random", "rand"):
            SETTINGS['control_flags'] = None
            return True
        elif re.fullmatch(r'[0-9A-Fa-f]{1,5}', v):
            SETTINGS['control_flags'] = int(v, 16) & 0xFFFFF
            return True
    
    elif n == 5:
        try:
            threads = int(v)
            if 1 <= threads <= 16:
                SETTINGS['threads'] = threads
                return True
        except ValueError:
            pass
    
    elif n == 6:  # Алгоритм
        if v.lower() in ("ctr", "0"):
            SETTINGS['algorithm'] = 0
            return True
        elif v.lower() in ("gcm", "1"):
            SETTINGS['algorithm'] = 1
            return True
        elif v.lower() in ("cbc", "2"):
            SETTINGS['algorithm'] = 2
            return True
    
    elif n == 7:  # Сжатие
        if v.lower() in ("none", "0"):
            SETTINGS['compression'] = 0
            return True
        elif v.lower() in ("fast", "1"):
            SETTINGS['compression'] = 1
            return True
        elif v.lower() in ("optimal", "2"):
            SETTINGS['compression'] = 2
            return True
        elif v.lower() in ("max", "3"):
            SETTINGS['compression'] = 3
            return True
    
    elif n == 8:  # Режим алфавита
        if v.lower() in ("auto", "0"):
            SETTINGS['alphabet_mode'] = 0
            return True
        elif v.lower() in ("universal", "1"):
            SETTINGS['alphabet_mode'] = 1
            return True
        elif v.lower() in ("russian", "ru", "2"):
            SETTINGS['alphabet_mode'] = 2
            return True
        elif v.lower() in ("english", "en", "3"):
            SETTINGS['alphabet_mode'] = 3
            return True
    
    return False

def settings(args=None):
    if args:
        any_ok = False
        for token in args.split():
            if apply_setting_direct(token): 
                any_ok = True
            else: 
                print(get_text("invalid_args", "Неверные аргументы").format("settings"))
                return
        if any_ok: 
            print(get_text("updated", "Настройки обновлены"))
        return
    
    print(get_text("settings", "Настройки"))
    debug_status = get_text("debug_on", "вкл") if SETTINGS['debug'] else get_text("debug_off", "выкл")
    hide_status = get_text("hide_on", "вкл") if SETTINGS['hide_key'] else get_text("hide_off", "выкл")
    
    # Алгоритмы
    algorithm_names = [get_text("algorithm_ctr"), get_text("algorithm_gcm"), get_text("algorithm_cbc")]
    algorithm_status = algorithm_names[SETTINGS['algorithm']]
    
    # Сжатие
    compression_names = [get_text("compression_none"), get_text("compression_fast"), 
                        get_text("compression_optimal"), get_text("compression_max")]
    compression_status = compression_names[SETTINGS['compression']]
    
    # Режим алфавита
    alphabet_names = [get_text("alphabet_auto"), get_text("alphabet_universal"), 
                     get_text("alphabet_russian"), get_text("alphabet_english")]
    alphabet_status = alphabet_names[SETTINGS['alphabet_mode']]
    
    print(f"1. {get_text('debug_mode', 'Режим отладки')} {debug_status}")
    print(f"2. {get_text('hide_key_mode', 'Скрытие ключа')} {hide_status}")
    print(f"3. language = {LANG}")
    control_display = f"{SETTINGS['control_flags']:05X}" if SETTINGS['control_flags'] is not None else get_text("debug_random", "случайный")
    print(f"4. control  = {control_display}")
    print(f"5. {get_text('threads', 'Потоки')} = {SETTINGS['threads']}")
    print(f"6. {get_text('algorithm', 'Алгоритм')} = {algorithm_status}")
    print(f"7. {get_text('compression', 'Сжатие')} = {compression_status}")
    print(f"8. {get_text('alphabet_mode', 'Режим алфавита')} = {alphabet_status}")
    print("by M1dAS_qq\n")
    
    while True:
        try:
            line = safe_input(get_text("prompt_set", "Введите изменение (n%значение) или Enter для выхода: ")).strip()
            if not line: 
                break
            
            any_ok = False
            for token in line.split():
                if apply_setting_direct(token): 
                    any_ok = True
                else: 
                    error("F1")
            
            if any_ok: 
                print(get_text("updated", "Настройки обновлены"))
                
        except KeyboardInterrupt:
            print()
            break
        except NonCriticalError:
            continue

def validate(text):
    """Проверяет текст на соответствие текущему алфавиту"""
    invalid_chars = []
    for ch in text:
        if ch not in CHAR_TO_BYTE:
            invalid_chars.append(ch)
    
    if invalid_chars:
        if SETTINGS['debug']:
            print(f"[DEBUG] Найдены недопустимые символы: {invalid_chars}")
        
        # Нормализуем текст автоматически
        normalized_text = normalize_text(text)
        if SETTINGS['debug']:
            print(f"[DEBUG] Текст автоматически нормализован")
        
        return normalized_text
    
    return text

def derive_hpc_key(seed, data_length):
    base_data = seed.to_bytes(2, 'big') + data_length.to_bytes(2, 'big')
    crc_value = crc32(base_data)
    key_bytes = crc_value.to_bytes(4, 'big') * 8
    
    if SETTINGS['debug']:
        debug_msg = get_text('debug_key_derivation', 'Вычисление ключа: CRC32={}').format(f'{crc_value:08X}')
        print(f"[DEBUG] {debug_msg}")
        print(f"[DEBUG] Ключ HPC: {key_bytes.hex().upper()}")
    
    return key_bytes

def process_text_with_hpc(text, seed, algorithm, compression, alphabet_id):
    """Обрабатывает текст с выбранным алфавитом"""
    # Устанавливаем алфавит для обработки
    initialize_alphabet(alphabet_id)
    
    # Нормализуем текст перед обработкой
    normalized_text = validate(text)
    
    text_bytes = text_to_bytes(normalized_text)
    
    if SETTINGS['debug']:
        debug_msg1 = get_text('debug_bytes_conversion', 'Преобразование: {} символов -> {} байт').format(len(normalized_text), len(text_bytes))
        print(f"[DEBUG] {debug_msg1}")
        print(f"[DEBUG] Используется алфавит: {alphabet_id}")
    
    # Применяем сжатие
    if compression > 0:
        compression_levels = [0, 1, 6, 9]
        level = compression_levels[compression]
        original_size = len(text_bytes)
        text_bytes = compress_data(text_bytes, level)
        if SETTINGS['debug']:
            print(f"[DEBUG] Сжатие: {original_size} -> {len(text_bytes)} байт (уровень {level})")
    
    # Используем длину сжатых данных для генерации ключа
    key_bytes = derive_hpc_key(seed, len(text_bytes))
    encrypted_data = encrypt_data(text_bytes, key_bytes, algorithm)
    
    if SETTINGS['debug']:
        print(f"[DEBUG] Зашифровано: {len(encrypted_data)} байт")
    
    return encrypted_data

def process_hpc_decryption(encrypted_data, seed, expected_length, algorithm, compression, alphabet_id):
    """Дешифрует данные с проверкой контрольной суммы"""
    # Устанавливаем алфавит для обработки
    initialize_alphabet(alphabet_id)
    
    # Вычисляем длину сжатых данных на основе алгоритма
    if algorithm == 0:  # CTR
        compressed_length = len(encrypted_data) - 16
    elif algorithm == 1:  # GCM
        compressed_length = len(encrypted_data) - 12 - 16
    elif algorithm == 2:  # CBC
        # Для CBC длина данных после удаления padding будет меньше
        # Используем expected_length как приблизительную оценку
        compressed_length = expected_length
    else:
        compressed_length = expected_length
    
    # Используем длину сжатых данных для генерации ключа
    key_bytes = derive_hpc_key(seed, compressed_length)
    
    try:
        decrypted_data = decrypt_data(encrypted_data, key_bytes, algorithm)
        
        # Применяем распаковку если было сжатие
        if compression > 0:
            original_size = len(decrypted_data)
            decrypted_data = decompress_data(decrypted_data)
            if SETTINGS['debug']:
                print(f"[DEBUG] Распаковано: {original_size} -> {len(decrypted_data)} байт")
        
        if SETTINGS['debug']:
            print(f"[DEBUG] Расшифровано: {len(decrypted_data)} байт")
        
        return decrypted_data
    except Exception as e:
        if SETTINGS['debug']:
            print(f"[DEBUG] Ошибка дешифровки: {e}")
        error("D1")
        return b""

_AESCCM_TAG_LEN = 8
_AESCCM_NONCE_LEN = 7

def derive_aes_key_from_int(key_int: int) -> bytes:
    ikm = key_int.to_bytes(16, 'big')
    salt = (key_int & 0xFFFF).to_bytes(2, 'big')
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"rudeprog v42")
    return hkdf.derive(ikm)

def aead_encrypt_hashes_compact(hashes_bytes: bytes, key_int: int) -> str:
    aesccm = AESCCM(derive_aes_key_from_int(key_int), tag_length=_AESCCM_TAG_LEN)
    nonce = os.urandom(_AESCCM_NONCE_LEN)
    ct = aesccm.encrypt(nonce, hashes_bytes, None)
    return base64.a85encode(nonce + ct).decode()

def aead_decrypt_to_hashes_compact(s: str, key_int: int) -> bytes:
    try:
        raw = base64.a85decode(s.encode())
    except Exception:
        if re.fullmatch(r'[0-9A-Fa-f]+', s):
            raw = bytes.fromhex(s)
        else:
            error("B1")
            return b""
    
    if len(raw) < (_AESCCM_NONCE_LEN + _AESCCM_TAG_LEN + 1):
        error("B1")
        return b""
    
    nonce, ct = raw[:_AESCCM_NONCE_LEN], raw[_AESCCM_NONCE_LEN:]
    aesccm = AESCCM(derive_aes_key_from_int(key_int), tag_length=_AESCCM_TAG_LEN)
    
    try:
        return aesccm.decrypt(nonce, ct, None)
    except Exception:
        error("D1")
        return b""

def build_key_v42(data_crc32, creation_timestamp, local_identifier, hpc_seed, original_text_length, encryption_algorithm, compression_alphabet, compression_level):
    """Создает ключ v42 с новой структурой"""
    return (
        (data_crc32 & 0xFFFFFFFF) << 96 |
        (creation_timestamp & 0xFFFFFFFF) << 64 |
        (local_identifier & 0xFFFFFF) << 40 |
        (hpc_seed & 0x3FFF) << 26 |  # 14 бит
        (original_text_length & 0xFFF) << 14 |
        (encryption_algorithm & 0x3) << 12 |
        (compression_alphabet & 0x3) << 10 |
        (compression_level & 0x3) << 8 |
        (PROGRAM_VERSION & 0xFF)
    )

def parse_key_v42(key_int: int) -> dict:
    """Парсит ключ v42 с новой структурой"""
    return {
        "data_crc32": (key_int >> 96) & 0xFFFFFFFF,
        "creation_timestamp": (key_int >> 64) & 0xFFFFFFFF,
        "local_identifier": (key_int >> 40) & 0xFFFFFF,
        "hpc_seed": (key_int >> 26) & 0x3FFF,  # 14 бит
        "original_text_length": (key_int >> 14) & 0xFFF,
        "encryption_algorithm": (key_int >> 12) & 0x3,
        "compression_alphabet": (key_int >> 10) & 0x3,
        "compression_level": (key_int >> 8) & 0x3,
        "key_format_version": key_int & 0xFF
    }

def extract_args_from_brackets(input_string):
    if not input_string:
        return []
    
    args = []
    bracket_count = 0
    start = -1
    
    for i, char in enumerate(input_string):
        if char == '[':
            if bracket_count == 0:
                start = i + 1
            bracket_count += 1
        elif char == ']':
            if bracket_count > 0:
                bracket_count -= 1
                if bracket_count == 0 and start != -1:
                    args.append(input_string[start:i])
                    start = -1
    
    return args

def show_help(command=None):
    if command is None:
        print(get_text("help"))
    else:
        command_lower = command.lower()
        help_key = f"help_{command_lower}"
        
        if command_lower == "settings":
            print(get_text("help_settings"))
            print(f"\n{get_text('settings', 'Настройки')}:")
            print("1. debug: 0/off или 1/on")
            print("2. hide_key: 0/off или 1/on") 
            print("3. language: ru/en")
            print("4. control_flags: random или hex (1-5 цифр)")
            print("5. threads: 1-16")
            print("6. algorithm: ctr/0, gcm/1, cbc/2")
            print("7. compression: none/0, fast/1, optimal/2, max/3")
            print("8. alphabet: auto/0, universal/1, russian/2, english/3")
            print(f"\n{get_text('help_exit').strip()}")
        else:
            help_text = get_text(help_key)
            if help_text and not help_text.startswith("[MISSING:"):
                print(help_text)
            else:
                print(get_text("idk"))

def mode_encrypt_cli(text=None):
    while True:
        try:
            if text is not None:
                t = text.strip()
            else:
                t = safe_input(get_text("enter_text", "Введите текст (до 4000 символов): ")).strip()
            
            if not t:
                return
            
            # Определяем алфавит
            if SETTINGS['alphabet_mode'] == 0:  # авто
                alphabet_id = detect_language(t)
            else:
                alphabet_id = SETTINGS['alphabet_mode'] - 1  # 1->0, 2->1, 3->2
            
            # Устанавливаем алфавит для обработки
            initialize_alphabet(alphabet_id)
            
            # Валидируем и нормализуем текст
            t = validate(t)
            
            if len(t) > MAX_TEXT_LENGTH:
                print(get_text("warning_text_too_long", "Предупреждение: текст обрезан до 4000 символов"))
                t = t[:MAX_TEXT_LENGTH]
            
            original_length = len(t)
            
            hpc_seed = int.from_bytes(os.urandom(2), "big") & 0x3FFF  # 14 бит
            
            # Генерируем Lid если не задан
            if SETTINGS['control_flags'] is not None:
                local_identifier = SETTINGS['control_flags']
            else:
                local_identifier = int.from_bytes(os.urandom(3), "big") & 0xFFFFFF
            
            creation_timestamp = int(time.time())
            encryption_algorithm = SETTINGS['algorithm']
            compression_level = SETTINGS['compression']
            
            hpc_bytes = process_text_with_hpc(t, hpc_seed, encryption_algorithm, compression_level, alphabet_id)
            data_crc32 = crc32(hpc_bytes)
            
            key_int = build_key_v42(data_crc32, creation_timestamp, local_identifier, hpc_seed, 
                                  original_length, encryption_algorithm, alphabet_id, compression_level)
            
            if SETTINGS['hide_key']:
                mask = os.urandom(2)
                extended_mask = mask * 8
                key_bytes = key_int.to_bytes(16, 'big')
                encrypted_key_bytes = bytes(a ^ b for a, b in zip(key_bytes, extended_mask))
                cipher_data = hpc_bytes + mask
                out_str = base64.a85encode(cipher_data).decode()
                
                print(f"\n{out_str}")
                print(encrypted_key_bytes.hex().upper())
            else:
                out_str = aead_encrypt_hashes_compact(hpc_bytes, key_int)
                print(f"\n{get_text('cipher', 'Шифр')} {out_str}")
                print(f"{get_text('key', 'Ключ')} {key_int:032X}")
            
            key_info = parse_key_v42(key_int)
            
            # Отображаем информацию о ключе
            algorithm_names = [get_text("algorithm_ctr"), get_text("algorithm_gcm"), get_text("algorithm_cbc")]
            compression_names = [get_text("compression_none"), get_text("compression_fast"), 
                                get_text("compression_optimal"), get_text("compression_max")]
            alphabet_names = [get_text("alphabet_universal"), get_text("alphabet_russian"), get_text("alphabet_english")]
            
            algorithm_name = algorithm_names[key_info['encryption_algorithm']] if key_info['encryption_algorithm'] < 3 else get_text("algorithm_unknown")
            compression_name = compression_names[key_info['compression_level']] if key_info['compression_level'] < 4 else "unknown"
            alphabet_name = alphabet_names[key_info['compression_alphabet']] if key_info['compression_alphabet'] < 3 else "unknown"
            
            print(f"\n{get_text('key_info', 'Информация из ключа')}")
            print(f"{get_text('text_length', 'Длина текста')} {key_info['original_text_length']}")
            print(f"{get_text('timestamp', 'Время создания')} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(key_info['creation_timestamp']))}")
            print(f"{get_text('version', 'Версия')} {key_info['key_format_version']}")
            print(f"{get_text('local_identifier', 'Локальный ID')} {key_info['local_identifier']:06X}")
            print(f"{get_text('hpc_seed', 'Сид HPC')} {key_info['hpc_seed']:04X}")
            print(f"{get_text('data_crc32', 'Контрольная сумма')} {key_info['data_crc32']:08X}")
            print(f"{get_text('algorithm', 'Алгоритм')} {algorithm_name}")
            print(f"{get_text('compression', 'Сжатие')} {compression_name}")
            print(f"{get_text('alphabet_mode', 'Режим алфавита')} {alphabet_name}")
            
            if SETTINGS['debug']:
                debug_msg = get_text('debug_final_result', 'Результат: {} -> {}').format(t, out_str[:20] + '...')
                print(f"[DEBUG] {debug_msg}")
            
            break
            
        except KeyboardInterrupt:
            print()
            return
        except NonCriticalError:
            if text is not None:
                return
            continue

def mode_decrypt_cli(cipher=None, key=None):
    while True:
        try:
            if cipher is not None:
                eh = cipher.strip()
            else:
                eh = safe_input(get_text("enter_cipher_hidden" if SETTINGS['hide_key'] else "enter_cipher", "Введите шифр: ")).strip()
            
            if not eh:
                return
            
            if key is not None:
                kh = key.strip().upper()
            else:
                kh = safe_input(get_text("enter_key_hidden" if SETTINGS['hide_key'] else "enter_key", "Введите ключ: ")).strip().upper()
            
            if not kh:
                return
            
            if SETTINGS['hide_key']:
                try:
                    cipher_data = base64.a85decode(eh.encode())
                    mask, hpc_bytes = cipher_data[-2:], cipher_data[:-2]
                    extended_mask = mask * 8
                    encrypted_key_bytes = bytes.fromhex(kh)
                    key_bytes = bytes(a ^ b for a, b in zip(encrypted_key_bytes, extended_mask))
                    key_int = int.from_bytes(key_bytes, 'big')
                    encrypted_bytes = hpc_bytes
                except:
                    error("B2")
                    continue
            else:
                try:
                    key_int = int(kh, 16)
                    encrypted_bytes = aead_decrypt_to_hashes_compact(eh, key_int)
                except:
                    error("B2")
                    continue
            
            if not encrypted_bytes:
                print(get_text("no_data", "Нет данных для обработки"))
                continue
            
            key_info = parse_key_v42(key_int)
            
            if key_info['key_format_version'] != PROGRAM_VERSION:
                print(get_text("warning_version_mismatch", "Внимание: версия ключа {} не совпадает с ожидаемой 42").format(key_info['key_format_version']))
            
            # Отображаем информацию о ключе
            algorithm_names = [get_text("algorithm_ctr"), get_text("algorithm_gcm"), get_text("algorithm_cbc")]
            compression_names = [get_text("compression_none"), get_text("compression_fast"), 
                                get_text("compression_optimal"), get_text("compression_max")]
            alphabet_names = [get_text("alphabet_universal"), get_text("alphabet_russian"), get_text("alphabet_english")]
            
            algorithm_name = algorithm_names[key_info['encryption_algorithm']] if key_info['encryption_algorithm'] < 3 else get_text("algorithm_unknown")
            compression_name = compression_names[key_info['compression_level']] if key_info['compression_level'] < 4 else "unknown"
            alphabet_name = alphabet_names[key_info['compression_alphabet']] if key_info['compression_alphabet'] < 3 else "unknown"
            
            print(f"\n{get_text('key_info', 'Информация из ключа')}")
            print(f"{get_text('text_length', 'Длина текста')} {key_info['original_text_length']}")
            print(f"{get_text('timestamp', 'Время создания')} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(key_info['creation_timestamp']))}")
            print(f"{get_text('version', 'Версия')} {key_info['key_format_version']}")
            print(f"{get_text('local_identifier', 'Локальный ID')} {key_info['local_identifier']:06X}")
            print(f"{get_text('hpc_seed', 'Сид HPC')} {key_info['hpc_seed']:04X}")
            print(f"{get_text('data_crc32', 'Контрольная сумма')} {key_info['data_crc32']:08X}")
            print(f"{get_text('algorithm', 'Алгоритм')} {algorithm_name}")
            print(f"{get_text('compression', 'Сжатие')} {compression_name}")
            print(f"{get_text('alphabet_mode', 'Режим алфавита')} {alphabet_name}")
            
            print(f"\n{get_text('processing', 'Обработка...')}")
            t0 = time.time()
            
            decrypted_bytes = process_hpc_decryption(
                encrypted_bytes, 
                key_info['hpc_seed'], 
                key_info['original_text_length'],
                key_info['encryption_algorithm'],
                key_info['compression_level'],
                key_info['compression_alphabet']
            )
            
            # ПРОВЕРКА КОНТРОЛЬНОЙ СУММЫ
            computed_crc = crc32(decrypted_bytes)
            if computed_crc != key_info['data_crc32']:
                if SETTINGS['debug']:
                    debug_msg = get_text('debug_crc_check', 'Проверка CRC: ожидается {}, получено {}').format(
                        f"{key_info['data_crc32']:08X}", f"{computed_crc:08X}")
                    print(f"[DEBUG] {debug_msg}")
                print(get_text("warning_crc_mismatch", "Внимание: контрольная сумма не совпадает - возможна ошибка в данных"))
                # Не прерываем выполнение, но предупреждаем пользователя
            
            recovered_text = bytes_to_text(decrypted_bytes)[:key_info['original_text_length']]
            
            total_time = time.time() - t0
            
            if len(recovered_text) != key_info['original_text_length']:
                print(get_text("warning_length_mismatch", "Внимание: длина восстановленного текста ({}) не совпадает с ожидаемой ({})").format(len(recovered_text), key_info['original_text_length']))
            
            print(f"\n{get_text('recovered', 'Восстановленный текст')} {recovered_text}")
            print(f"{get_text('time', 'Общее время')} {total_time:.2f} s")
            
            if SETTINGS['debug']:
                debug_msg = get_text('debug_final_result', 'Результат: {} -> {}').format(eh[:20] + '...', recovered_text)
                print(f"[DEBUG] {debug_msg}")
            
            break
            
        except KeyboardInterrupt:
            print()
            return
        except NonCriticalError:
            if cipher is not None and key is not None:
                return
            continue

def main():
    print(get_text("banner", "rude - v42\n"))
    mode = None
    
    while True:
        try:
            cmd_input = safe_input(f"{get_text('cmd', 'Введите команду')} [{mode or '-'}] ").strip()
            
            if not cmd_input:
                if mode == "encrypt":
                    print(get_text("encrypt_mode", "Режим шифрования."))
                    mode_encrypt_cli()
                elif mode == "decrypt":
                    print(get_text("decrypt_mode", "Режим дешифровки."))
                    mode_decrypt_cli()
                continue
            
            parts = cmd_input.split(maxsplit=1)
            cmd, args_string = parts[0], parts[1] if len(parts) > 1 else ""
            args_list = extract_args_from_brackets(args_string)
            
            if cmd == "%mode1":
                mode = "encrypt"
                print(get_text("encrypt_mode", "Режим шифрования."))
                if len(args_list) > 1:
                    print(get_text("invalid_args_count", "Неверное количество аргументов. Ожидается {}. Воспользуйтесь командой \"%help [{}]\".").format(1, "mode1"))
                elif args_list:
                    mode_encrypt_cli(args_list[0])
                else:
                    mode_encrypt_cli()
                    
            elif cmd == "%mode2":
                mode = "decrypt"
                print(get_text("decrypt_mode", "Режим дешифровки."))
                if len(args_list) > 2:
                    print(get_text("invalid_args_count", "Неверное количество аргументов. Ожидается {}. Воспользуйтесь командой \"%help [{}]\".").format(2, "mode2"))
                elif len(args_list) == 2:
                    mode_decrypt_cli(args_list[0], args_list[1])
                elif len(args_list) == 1:
                    print(get_text("invalid_args_count", "Неверное количество аргументов. Ожидается {}. Воспользуйтесь командой \"%help [{}]\".").format(2, "mode2"))
                else:
                    mode_decrypt_cli()
                    
            elif cmd == "%settings":
                if len(args_list) > 1:
                    print(get_text("invalid_args_count", "Неверное количество аргументов. Ожидается {}. Воспользуйтесь командой \"%help [{}]\".").format(1, "settings"))
                elif args_list:
                    settings(args_list[0])
                else:
                    settings()
                    
            elif cmd == "%help":
                if len(args_list) > 1:
                    print(get_text("invalid_args_count", "Неверное количество аргументов. Ожидается {}. Воспользуйтесь командой \"%help [{}]\".").format(1, "help"))
                elif args_list:
                    show_help(args_list[0])
                else:
                    show_help()
                    
            elif cmd == "%exit":
                print(get_text("goodbye", "Программа завершена. До свидания!"))
                break
                
            else:
                print(get_text("idk", "Неизвестная команда. Используйте %help для справки"))
                
        except KeyboardInterrupt:
            print()
            continue
        except NonCriticalError:
            continue

if __name__ == '__main__':
    main()
#by M1dAS_qq