# Python tools

Вспомогательные скрипты на Python для проекта go-client-classifier (тесты антибот-обхода и др.).

## Требования

- Python 3.12+
- [Poetry](https://python-poetry.org/docs/#installation)

## Установка (деплой окружения)

Из корня репозитория:

```bash
cd tools/python
poetry install
```

Или из любой директории:

```bash
poetry install --directory tools/python
```

После этого окружение с зависимостями готово к использованию.

## Запуск скриптов

Все команды выполняйте из `tools/python` после `poetry install`, либо через `poetry run`:

```bash
cd tools/python
poetry run python antibot_test.py
```

Или активируйте shell и запускайте скрипты как обычно:

```bash
cd tools/python
poetry shell
python antibot_test.py
```

## Что внутри

- **antibot_test.py** — проверка обхода антибот-детекции через [curl_cffi](https://github.com/yifeikong/curl_cffi) (TLS/HTTP2 fingerprint под Chrome/Safari). Зависимость: `curl-cffi`.

## Зависимости

Управляются через Poetry, см. `pyproject.toml`. Основная зависимость: `curl-cffi`.

Добавление новой зависимости:

```bash
cd tools/python
poetry add <package>
```

Обновление lock-файла после правок `pyproject.toml`:

```bash
poetry lock
poetry install
```
