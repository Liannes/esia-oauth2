# -*- coding: utf-8 -*-
# Код основан на пакете esia-connector
# https://github.com/eigenmethod/esia-connector
# Лицензия:
#   https://github.com/eigenmethod/esia-connector/blob/master/LICENSE.txt
# Copyright (c) 2015, Septem Capital
import base64
import datetime
import json
import os
import tempfile

import pytz

from subprocess import Popen, PIPE
import getpass

import requests

from .exceptions import CryptoBackendError, HttpError, IncorrectJsonError


def make_request(url, method='GET', headers=None, data=None, verify=True):
    """
    Выполняет запрос по заданному URL и возвращает dict на основе JSON-ответа

    :param str url: URL-адрес
    :param str method: (optional) HTTP-метод запроса, по умолчанию GET
    :param dict headers: (optional) массив HTTP-заголовков, по умолчанию None
    :param dict data: (optional) массив данных передаваемых в запросе,
        по умолчанию None
    :param boolean verify: optional, производить ли верификацию
        ssl-сертификата при запросае
    :return: dict на основе JSON-ответа
    :rtype: dict
    :raises HttpError: если выбрасыватеся исключение requests.HTTPError
    :raises IncorrectJsonError: если JSON-ответ не может быть
        корректно прочитан
    """
    try:
        response = requests.request(
            method, url, headers=headers, data=data, verify=verify)
        response.raise_for_status()
        return json.loads(response.content)
    except requests.HTTPError as e:
        raise HttpError(e)
    except ValueError as e:
        raise IncorrectJsonError(e)


def csp_sign(container_name, container_password, csp_path, data):
    """
    Подписывает данные с использованием ГОСТ Р 34.10-2012 открепленной подписи.
    В качестве бэкенда используется утилита cryptcp из ПО КриптоПРО CSP.
    :param str system: Название системы
    :param str container_name: Название контенйера
    :param str container_password: Пароль для контейнера закрытого ключа
    :param str csp_path: Путь до Крипто-программы
    :param str data: Подписываемый текст
    :raises CryptoBackendError: Произошла ошибка при подписании
    """

    # Получаем темп путь
    tmp_dir = tempfile.gettempdir()
    # Записываем текст
    with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=tmp_dir) as f:
        # Название файла
        in_path = f.name
        f.write(data)
        f.close()
    # Название файла на выходе
    out_path = in_path + '.sig'
    try:
        if container_password == '':
            cmd = (
                f"{csp_path} -keys -cont {container_name} -sign GOST12_256 -in {in_path} -out {out_path} -keytype exchange -silent")
            os.system(cmd)
        else:
            cmd = (
                f"{csp_path} -keys -cont {container_name} -password {container_password} -sign GOST12_256 -in {in_path} -out {out_path} -keytype exchange -silent")
            os.system(cmd)

        with open(out_path, 'rb') as f:
            data = f.read()
            signed_message = bytes(reversed(data))
            f.close()

        os.unlink(in_path)
        os.unlink(out_path)

        return signed_message

    except Exception as e:
        raise CryptoBackendError(e)


def sign_params(params, settings):
    """
    Подписывает параметры запроса и добавляет в params ключ client_secret.
    Подпись основывается на полях:
        `client_id`, `scope`, `scope_org`, `timestamp`, `state`, `redirect_uri`.
    :param dict params: параметры запроса
    :param EsiaSettings settings: настройки модуля ЕСИА
    :return: подписанные параметры запроса
    :rtype: dict
    """
    plaintext = params.get('client_id') + params.get('scope') + params.get('scope_org') + params.get('timestamp') + \
        params.get('state') + params.get('redirect_uri')

    raw_client_secret = csp_sign(
        settings.csp_certificate_name,
        settings.csp_certificate_pass,
        settings.csptest_path, plaintext)

    params.update(
        client_secret=base64.urlsafe_b64encode(
            raw_client_secret).decode('utf-8'),
    )
    return params


def get_timestamp():
    """
    Возвращает текущую дату и время в строковом представлении с указанем зоны
    в формате пригодном для использования при взаимодействии с ЕСИА

    :return: текущая дата и время
    :rtype: str
    """
    return datetime.datetime.now(pytz.timezone('Europe/Moscow')).\
        strftime('%Y.%m.%d %H:%M:%S %z').strip()
