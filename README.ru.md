
# ObfUtil - Продвинутый инструмент шифрования и обфускации

![Version](https://img.shields.io/badge/version-3.4-blue)
![Python](https://img.shields.io/badge/python-3.9+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

[Возможности](#-возможности) • [Установка](#-установка) • [Быстрый старт](#-быстрый-старт) • [Команды сейфов](#-команды-сейфов) • [API](#-python-api) • [История изменений](CHANGELOG.md)

## 📖 Содержание

- [Возможности](#-возможности)
- [Установка](#-установка)
- [Быстрый старт](#-быстрый-старт)
- [Команды шифрования](#-команды-шифрования)
- [Команды сейфов](#-команды-сейфов)
- [Защита целостности](#-защита-целостности)
- [Обфускация кода](#-обфускация-кода)
- [Python API](#-python-api)
- [Конфигурация](#-конфигурация)
- [Участие в разработке](#-участие-в-разработке)
- [Лицензия](#-лицензия)

## ✨ Возможности

| Категория | Описание |
|-----------|----------|
| **Шифрование** | AES-256, Пароль/Ключевой файл, Проверка целостности HMAC |
| **Сейфы** | Зашифрованные контейнеры, Организация файлов, Статистика, Использование диска |
| **Поиск** | Поиск по шаблону, Поиск по расширению, Фильтры по размеру, Регистр |
| **Обфускация** | AST-обфускация, Переименование переменных, Шифрование строк, Защита от изменений |
| **Пакетные операции** | Множественное шифрование, Индикатор прогресса, Статистика скорости |
| **Многоязычность** | Русский, Английский, Немецкий |
| **Безопасность** | Безопасная очистка памяти, Защита от подбора паролей, Проверка хэшей |

## 📦 Установка

### Из GitHub (Рекомендуется)

```bash
# Клонирование репозитория
git clone https://github.com/fearvbs/obfutil.git
cd obfutil

# Установка в режиме разработки
pip install -e .
```

### Из PyPI

```bash
pip install obfutil
```

### Проверка установки

```bash
obfutil --help
obfutil vault --help
```

## 🚀 Быстрый старт

### Базовое шифрование

```bash
# Шифрование с паролем
obfutil encrypt secret.txt --password

# Расшифровка и редактирование
obfutil decrypt secret.txt.enc --password

# Просмотр содержимого
obfutil view secret.txt.enc --password
```

### Операции с сейфами

```bash
# Создание сейфа
obfutil vault create mydocs --size 100 --password

# Добавление файлов
obfutil vault add mydocs document.pdf --password

# Просмотр содержимого
obfutil vault preview mydocs --password

# Извлечение файла
obfutil vault extract mydocs document.pdf ./output.pdf --password
```

## 🔐 Команды шифрования

### Шифрование с паролем

```bash
# Шифрование
obfutil encrypt file.txt --password

# Расшифровка с редактированием
obfutil decrypt file.txt.enc --password

# Только просмотр
obfutil view file.txt.enc --password
```

### Шифрование с ключевым файлом

```bash
# Генерация ключа
obfutil --gen-key

# Шифрование с ключом
obfutil encrypt file.txt --key-file

# Расшифровка с ключом
obfutil decrypt file.txt.enc --key-file
```

### Пакетные операции

```bash
# Шифрование всех текстовых файлов
obfutil batch-encrypt *.txt --password

# Расшифровка всех зашифрованных файлов
obfutil batch-decrypt *.enc --password
```

## 📁 Команды сейфов

Сейфы - это зашифрованные контейнеры для хранения нескольких файлов.

### Управление сейфами

| Команда | Описание | Пример |
|---------|----------|--------|
| `create` | Создать сейф | `obfutil vault create myvault --size 100 --password` |
| `list` | Список сейфов | `obfutil vault list` |
| `info` | Информация о сейфе | `obfutil vault info myvault --password` |
| `delete` | Безопасное удаление | `obfutil vault delete myvault` |


### Операции с файлами

| Команда | Описание | Пример |
|---------|----------|--------|
| `add` | Добавить файл | `obfutil vault add myvault file.txt --password` |
| `extract` | Извлечь файл | `obfutil vault extract myvault file.txt ./out.txt --password` |
| `remove` | Удалить файл | `obfutil vault remove myvault file.txt --password` |
| `rename` | Переименовать файл | `obfutil vault rename myvault old.txt new.txt --password` |

### Расширенные команды (Новое в 3.4)

| Команда | Описание | Пример |
|---------|----------|--------|
| `stats` | Детальная статистика | `obfutil vault stats myvault --password` |
| `du` | Использование диска | `obfutil vault du myvault --password` |
| `search` | Поиск файлов | `obfutil vault search myvault "*.pdf" --password` |
| `preview` | Быстрый просмотр | `obfutil vault preview myvault --password` |
| `verify` | Проверка целостности | `obfutil vault verify myvault --deep --password` |
| `storage` | Использование хранилища | `obfutil vault storage myvault --password` |

### Опции команды add

```bash
# Добавление с внутренним путем
obfutil vault add myvault file.txt docs/file.txt --password

# Добавление с удалением оригинала (перемещение)
obfutil vault add myvault file.txt --password --move

# Перезапись существующего файла
obfutil vault add myvault file.txt --password --force
```

### Фильтры поиска

```bash
# Поиск по шаблону
obfutil vault search myvault "*.pdf" --password

# Поиск по расширению
obfutil vault search myvault "jpg" --type ext --password

# Поиск по подстроке
obfutil vault search myvault "секрет" --type contains --password

# Поиск с фильтрами по размеру
obfutil vault search myvault "*.mp4" --min-size 10 --max-size 100 --password

# Поиск с учетом регистра
obfutil vault search myvault "README" --case --password
```

### Пример вывода статистики

```
=== Статистика сейфа: myvault ===
==================================================
Всего файлов:   47
Общий размер:   128.5 MB
Средний размер: 2.7 MB

Самый большой:  video.mp4 (45.2 MB)
Самый старый:   config.ini (2024-01-15)
Самый новый:    report.pdf (2026-03-23)

Типы файлов:
  .pdf    12 файлов   45.2 MB  ████████████████░░░░░░░░░░░░░░
  .jpg     8 файлов   32.1 MB  ████████████░░░░░░░░░░░░░░░░░░
  .txt    15 файлов    0.8 MB  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  .mp4     1 файл     45.2 MB  ████████████████░░░░░░░░░░░░░░
```

## 🛡️ Защита целостности

```bash
# Шифрование с проверкой целостности
obfutil encrypt-int sensitive.doc --password

# Проверка целостности файла
obfutil verify-int sensitive.doc.enc --password

# Расшифровка с проверкой целостности
obfutil decrypt-int sensitive.doc.enc --password
```

## 🔧 Обфускация кода

```bash
# Обфускация Python скрипта
obfutil obfuscate script.py

# Результат: script_obf.py
```

Возможности обфускации:
- Случайные имена переменных
- Шифрование строк
- Разделение кода
- Защита от изменений
- Внедрение мусорного кода

## 🐍 Python API

```python
from obfutil.core.api import api

# Шифрование файла
result = api.encrypt_file("document.txt", password="secret")
if result['success']:
    print(f"Зашифровано: {result['output_path']}")

# Операции с сейфами
api.create_vault("myvault", size_mb=100, password="vaultpass")
api.add_file_to_vault("myvault", "file.txt", password="vaultpass")

# Получение статистики
stats = api.get_vault_statistics("myvault", password="vaultpass")
print(f"Файлов: {stats['total_files']}, Размер: {stats['total_size_mb']} MB")

# Поиск файлов
files = api.search_files_in_vault("myvault", "*.pdf", password="vaultpass")
for file in files:
    print(f"Найден: {file['path']} ({file['size_kb']} KB)")

# Пакетные операции
result = api.encrypt_files_batch(["file1.txt", "file2.txt"], password="secret")
print(f"Обработано: {result['successful']}/{result['processed']} файлов")
```

## ⚙️ Конфигурация

Все данные хранятся в `~/.obfutil/`:

```
~/.obfutil/
├── config.ini          # Конфигурация пользователя
├── vaults/             # Зашифрованные сейфы
│   ├── myvault.obfvault
│   └── vaults.json     # Реестр сейфов
├── logs/               # Логи операций
│   └── program.log
└── secret.key          # Ключ шифрования (если создан)
```

### Команды конфигурации

```bash
# Показать текущую конфигурацию
obfutil config --show

# Сменить язык
obfutil config --lang ru     # Русский
obfutil config --lang de     # Немецкий
obfutil config --lang en     # Английский

# Генерация пароля
obfutil --gen-pass 16

# Генерация ключа
obfutil --gen-key
```

## 🖥️ Системные требования

- **Python**: 3.9 или выше
- **Зависимости**: cryptography, astor
- **Платформы**: Windows, Linux ( не протестирован на данный момент )
- **Хранилище**: Директория ~/.obfutil/ с правами на запись

## 🤝 Участие в разработке

1. Форкните репозиторий
2. Создайте ветку для новой функции (`git checkout -b feature/amazing-feature`)
3. Зафиксируйте изменения (`git commit -m 'Add amazing feature'`)
4. Отправьте в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## 📄 Лицензия

MIT License - подробности в файле [LICENSE](LICENSE)

---

## 🌟 Основные улучшения версии 3.4

- 📊 **`vault stats`** - Детальная статистика файлов и распределение по типам
- 🔍 **`vault search`** - Мощный поиск с фильтрами по размеру и типу
- 📁 **`vault du`** - Анализ использования диска по папкам
- ✏️ **`vault rename`** - Переименование файлов внутри сейфов
- ⚡ **`--force`** - Перезапись существующих файлов
- 🛡️ **Улучшенная проверка хэшей** - Исправлена после операций переименования
- 🌐 **Улучшенные сообщения об ошибках** - Понятные подсказки для действий

---

*Полный список изменений в [CHANGELOG.md](CHANGELOG.md)*