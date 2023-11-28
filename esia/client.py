# -*- coding: utf-8 -*-
# Код основан на пакете esia-connector
# https://github.com/eigenmethod/esia-connector
# Лицензия:
#   https://github.com/eigenmethod/esia-connector/blob/master/LICENSE.txt
# Copyright (c) 2015, Septem Capital
import os
import os.path
import uuid
import json
import base64

try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

try:
    from urllib.parse import quote_plus, urlencode
except ImportError:
    from urllib import quote_plus, urlencode

import jwt
from jwt.exceptions import InvalidTokenError

from .exceptions import (
    ConfigError, CryptoBackendError, IncorrectMarkerError)

from .utils import get_timestamp, make_request, sign_params


class EsiaSettings(object):
    def __init__(
            self, esia_client_id,
            redirect_uri,
            esia_service_url,
            esia_scope,
            esia_scope_org,
            esia_token_check_key=None,
            logout_redirect_uri=None,
            csptest_path='',
            csp_certificate_name='',
            csp_certificate_pass='',
            csp_certificate_hash='',
            ssl_verify=True
    ):
        """
        Класс настроек ЕСИА
        :param str esia_client_id: мнемоника клиента (Можно узнать в заявке, либо через тех.портале ЕСИА)
        :param str redirect_uri: URI по которому браузер будет перенаправленпосле ввода учетных данны в ЕСИА
        :param str esia_service_url: базовый URL сервиса ЕСИА
        :param str esia_scope: список scope для пользователей, разделенный пробелами (Таблица 67 в методичке ЕСИА)
        :param str esia_scope_org: список scope для организации, разделенный пробелами (Таблица 67 в методичке ЕСИА)
        :param str or None esia_token_check_key: путь к публичному ключу для проверки JWT (access token) необходимо запросить у технической поддержки ЕСИА
        :param str csptest_path: указать путь к csptest-программе в пакете Крипто-Про CSP (Стандартный путь windows: '"C:\Program Files (x86)\Crypto Pro\CSP\csptest.exe"', Linux: 'csptest' (Объявить полный путь в PATH, пример: ln -s /opt/cprocsp/bin/amd64/csptest /usr/bin/csptest) )
        :param str csp_certificate_name: указать название контейнера (csptest -keyset -enum_cont -fqcn -verifyc). Для Windows: '\\\\\\\\\\\\\\\\.\\\\\\\\REGISTRY\\\\\\\\XXXXXX', для Linux: '"\\\\\\\\\\\\\\\\\\\\\\\\.\\\\\\\\HDIMAGE\\\\\\\\XXXXXX"'
        :param sty csp_certificate_pass: пароль для контейнера (если пароля нет, то поставить "")
        :param str csp_certificate_hash: хэш-сертификата полученного через утилиту ЕСИА (http://esia.gosuslugi.ru/public/calc_cert_hash_unix.zip)
        :param boolean ssl_verify: optional, производить ли верификацию ssl-сертификата при запросах к сервису ЕСИА?
        """
        self.esia_client_id = esia_client_id
        self.redirect_uri = redirect_uri
        self.esia_service_url = esia_service_url
        self.esia_scope = esia_scope
        self.esia_scope_org = esia_scope_org
        self.esia_token_check_key = esia_token_check_key
        self.csptest_path = csptest_path
        self.csp_certificate_name = csp_certificate_name
        self.csp_certificate_pass = csp_certificate_pass
        self.csp_certificate_hash = csp_certificate_hash
        self.logout_redirect_uri = logout_redirect_uri
        self.ssl_verify = ssl_verify

        if not self.csptest_path:
            raise ConfigError('No path to csptest')
        if not self.csp_certificate_name:
            raise ConfigError('Container name is not specified')


class EsiaAuth(object):
    """
    Класс отвечает за OAuth2 авторизацию черещ ЕСИА
    """
    _ESIA_ISSUER_NAME = 'http://esia.gosuslugi.ru/'
    _AUTHORIZATION_URL = '/aas/oauth2/v2/ac'
    _TOKEN_EXCHANGE_URL = '/aas/oauth2/v2/te'
    _LOGOUT_URL = '/idp/ext/Logout'

    def __init__(self, settings):
        """
        :param EsiaSettings settings: параметры ЕСИА-клиента
        """
        self.settings = settings

    def get_auth_url(self):
        """
        Возвращает URL для перехода к авторизации в ЕСИА или для
        автоматического редиректа по данному адресу

        :return: url
        :rtype: str
        """
        params = {
            'client_id': self.settings.esia_client_id,
            'client_secret': '',
            'redirect_uri': self.settings.redirect_uri,
            'scope': self.settings.esia_scope,
            'response_type': 'code',
            'state': str(uuid.uuid4()),
            'timestamp': get_timestamp(),
            'access_type': 'offline',
            'scope_org': self.settings.esia_scope_org,
            'client_certificate_hash': self.settings.csp_certificate_hash
        }

        params = sign_params(params, self.settings)

        # sorted needed to make uri deterministic for tests.
        params = urlencode(sorted(params.items()))

        return '{base_url}{auth_url}?{params}'.format(
            base_url=self.settings.esia_service_url,
            auth_url=self._AUTHORIZATION_URL,
            params=params)

    def complete_authorization(
            self, code, state, validate_token=None, redirect_uri=None):
        """
        Завершает авторизацию. Обменивает полученный code на access token.
        При этом может опционально производить JWT-валидацию ответа на основе
        публичного ключа ЕСИА. Извлекает из ответа идентификатор пользователя
        и возвращает экземпляр ESIAInformationConnector для последующих
        обращений за данными пользователя.

        :param str code: Временный код полученный из GET-параметра,
            который обменивается на access token
        :param str state: UUID запроса полученный из GET-параметра
        :param boolean validate_token: производить ли JWT-валидацию
            ответа от ЕСИА (Временно пропущен)
        :param str or None redirect_uri: URI на который браузер был
            перенаправлен после авторизации
        :rtype: EsiaInformationConnector
        :raises IncorrectJsonError: если ответ содержит невалидный JSON
        :raises HttpError: если код HTTP ответа отличен от кода 2XX
        :raises IncorrectMarkerError: если validate_token=True и полученный
            токен не прошел валидацию
        """
        params = {
            'client_id': self.settings.esia_client_id,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.settings.redirect_uri,
            'timestamp': get_timestamp(),
            'token_type': 'Bearer',
            'scope': self.settings.esia_scope,
            'state': state,
            'scope_org': self.settings.esia_scope_org,
            'client_certificate_hash': self.settings.csp_certificate_hash
        }

        params = sign_params(
            params, self.settings
        )

        url = '{base_url}{token_url}'.format(
            base_url=self.settings.esia_service_url,
            token_url=self._TOKEN_EXCHANGE_URL
        )

        response_json = make_request(
            url=url, method='POST', data=params,
            verify=self.settings.ssl_verify)

        id_token = response_json['id_token']

        # if validate_token:
        #     payload = self._validate_token(id_token)
        # else:
        payload = self._parse_token(id_token)
        oid = payload['urn:esia:sbj']['urn:esia:sbj:oid']

        return EsiaInformationConnector(
            access_token=response_json['access_token'],
            oid=oid,
            settings=self.settings
        )

    def get_logout_url(self, redirect_uri=None):
        """
        Возвращает URL для выхода пользователя из ЕСИА (логаут)

        :param str or None redirect_uri: URI, по которому будет перенаправлен
            браузер после логаута
        :return: url
        :rtype: str
        """
        logout_url = '{base_url}{logout_url}?client_id={client_id}'.format(
            base_url=self.settings.esia_service_url,
            logout_url=self._LOGOUT_URL,
            client_id=self.settings.esia_client_id
        )

        redirect = (redirect_uri or self.settings.logout_redirect_uri)
        if redirect:
            logout_url += '&redirect_url={redirect}'.format(
                redirect=quote_plus(redirect))

        return logout_url

    @staticmethod
    def _parse_token(token):
        """
        :param str token: токен для декодирования
        :rtype: json
        """
        data = token.split('.')
        payload = data[1]

        source = base64.b64decode(payload).decode("utf-8")

        res = json.loads(source)

        return res

    @staticmethod
    def _get_user_id(payload):
        """
        :param dict payload: декодированные данные токена
        """
        return payload.get('urn:esia:sbj', {}).get('urn:esia:sbj:oid')

    def _validate_token(self, token):
        """
        :param str token: токен для валидации
        """
        if self.settings.esia_token_check_key is None:
            raise ValueError(
                "To validate token you need to specify "
                "`esia_token_check_key` in settings!")

        with open(self.settings.esia_token_check_key, 'r') as f:
            data = f.read()

        try:
            return jwt.decode(
                token, key=data,
                audience=self.settings.esia_client_id,
                issuer=self._ESIA_ISSUER_NAME
            )
        except InvalidTokenError as e:
            raise IncorrectMarkerError(e)


class EsiaInformationConnector(object):
    """
    Класс для получения данных от ЕСИА REST сервиса
    """

    def __init__(self, access_token, oid, settings):
        """
        :param str access_token: access token
        :param int oid: идентификатор объекта в ЕСИА
            (напрамер идентификатор персоны)
        :param EsiaSettings settings: параметры ЕСИА-клиента
        """
        self.token = access_token
        self.oid = oid
        self.settings = settings
        self._rest_base_url = '%s/rs' % settings.esia_service_url

    def esia_request(self, endpoint_url, accept_schema=None):
        """
        Формирует и направляет запрос к ЕСИА REST сервису и возвращает JSON

        :param str endpoint_url: endpoint URL
        :param str or None accept_schema: optional версия схемы ответа
            (влияет на формат ответа)
        :rtype: dict
        :raises IncorrectJsonError: если ответ содержит невалидный JSON
        :raises HttpError: если код HTTP ответа отличен от кода 2XX
        """
        headers = {
            'Authorization': "Bearer %s" % self.token
        }

        if accept_schema:
            headers['Accept'] = 'application/json; schema="%s"' % accept_schema
        else:
            headers['Accept'] = 'application/json'

        return make_request(
            url=endpoint_url, headers=headers,
            verify=self.settings.ssl_verify)

    def get_person_main_info(self, accept_schema=None):
        """
        Возвращает основные сведения о персоне
        Минимальный scope: openid, fullname
        :rtype: dict
        """
        url = '{base}/prns/{oid}'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_addresses(self, accept_schema=None):
        """
        Возвращает адреса персоны
        Минимальный scope: addresses
        :rtype: dict
        """
        url = '{base}/prns/{oid}/addrs?embed=(elements)'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_contacts(self, accept_schema=None):
        """
        Возвращает контактную информацию персоны
        Минимальный scope: email mobile
        :rtype: dict
        """
        url = '{base}/prns/{oid}/ctts?embed=(elements)'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_documents(self, accept_schema=None):
        """
        Возвращает документы персоны
        Минимальный scope: id_doc
        :rtype: dict
        """
        url = '{base}/prns/{oid}/docs?embed=(elements)'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_kids(self, accept_schema=None):
        """
        Возвращает информацию о детях персоны
        :rtype: dict
        """
        url = '{base}/prns/{oid}/kids?embed=(elements)'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_transport(self, accept_schema=None):
        """
        Возвращает информацию о транспортных средствах персоны
        :rtype: dict
        """
        url = '{base}/prns/{oid}//vhls?embed=(elements)'.format(
            base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_oid_user(self, accept_chema=None):
        return self.oid
