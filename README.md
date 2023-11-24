# esia-oauth2

## Модуль для доступа к ЕСИА REST сервису (https://esia.gosuslugi.ru)

Основан на коде esia-connector https://github.com/eigenmethod/esia-connector и https://github.com/sokolovs/esia-oauth2, лицензия: https://github.com/eigenmethod/esia-connector/blob/master/LICENSE.txt

### Позволяет:

- Сформировать ссылку для перехода на сайт ЕСИА с целью авторизации
- Завершает процедуру авторизации обменивая временный код на access token
- Опционально может производить JWT (JSON Web Token) валидацию ответа ЕСИА (при наличии публичного ключа ЕСИА)
- Для формирования открепленной подписи запросов, в качестве бэкенда может использоваться
  модуль M2Crypto или openssl через системный вызов (указывается в настройках)
- Выполнять информационные запросы к ЕСИА REST сервису для получения сведений о персоне:
  - Основаная информация
  - Адреса
  - Контактная информация
  - Документы
  - Дети
  - Транспортные средства

### Установка:

```
pip install --upgrade git+https://github.com/Liannes/esia-oauth2.git
pip install -r https://raw.githubusercontent.com/sokolovs/esia-oauth2/master/requirements.txt
```

### Предварительные условия

Для работы требуется наличие публичного и приватного ключа в соответствии с методическими рекомендациями
по работе с ЕСИА. Допускается использование самоподписного сертифката, который можно сгенерировать
следующей командой:

```
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -sha1 -keyout my_private.key -out my_public_cert.crt
```

Полученный в результате файл my_public_cert.crt должен быть привязан к информационной системе вашей организации
на сайте Госуслуг, а также направлен вместе с заявкой на доступ к ЕСИА
(подробнее см. документы http://minsvyaz.ru/ru/documents/?words=ЕСИА).

**Внимание!** С 01 апреля 2020 прекращается поддержка использования самоподписных сертификатов. Необходимо
получить ключ ГОСТ 2012 в одном из сертификационных центров и использовать алгоритм подписи ГОСТ Р 34.10-2012.
Для этого необходимо установить на сервере КриптоПРО CSP, установить контейнер с закрытым ключем, а так же
привязать сертификат связанный с закрытым ключем к своей информационной системе.

Для валидации ответов от ЕСИА потребуется публичный ключ, который можно запросить в технической поддержке ЕСИА,
уже после регистрации информационной системы и получения доступа к тестовой среде ЕСИА. Валидация опциональна.

### Пример использования в Django

Конфигурация

```
SETTINGS = EsiaSettings(
        esia_client_id='TESTAPP',
        redirect_uri='http://localhost:3000/return',
        unix='Windows',
        esia_token_check_key=get_file('esia_pub.key'),
        esia_service_url='https://esia.gosuslugi.ru',
        esia_scope='openid birthdate gender inn snils id_doc birthplace addresses',
        esia_scope_org='openid birthdate gender inn snils id_doc birthplace addresses',
        csptest_path='"C:\Program Files (x86)\Crypto Pro\CSP\csptest.exe"',
        csp_certificate_name=r'\\.\REGISTER\XXXXXXXXX',
        csp_certificate_pass='',
        csp_certificate_hash='DD4BB7C0BB340177A3021F5722AD7B16608BF1B28E143229CCC09812C604D8D',
    )
```

В свой urls.py добавьте:

```python
    path("api/esia_login",
         views.EsaiLoginRegistersView.as_view(), name='esia_login'),
    path("api/callback",
         views.EsiaLoginCallbackView.as_view(), name='esia_callback'),
```

В свой views.py добавьте:

```python
import json
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.views import logout
from esia.client import EsiaConfig, EsiaAuth

SETTINGS = EsiaSettings(...)

class EsaiLoginRegistersView(APIView):
    def get(self, request, format=None):
        esia_auth = EsiaAuth(SETTINGS)
        esia_login_url = esia_auth.get_auth_url()
        return Response(esia_login_url, status=status.HTTP_200_OK)


class EsiaLoginCallbackView(APIView):
    def post(self, request, foramt=None):
        esia_auth = EsiaAuth(SETTINGS)
        data = []
        code = request.data['code']
        state = request.data['state']
        esia_client = esia_auth.complete_authorization(
            code, state, validate_token=False)

        # Запрос информации о персоне
        main_info = esia_client.get_person_main_info()
        pers_doc = esia_client.get_person_documents()
        pars_addr = esia_client.get_person_addresses()
        pers_contacts = esia_client.get_person_contacts()
        pers_kids = esia_client.get_person_kids()
        pers_trans = esia_client.get_person_transport()
        data.append(main_info)
        data.append(pers_doc)
        data.append(pars_addr)
        data.append(pers_contacts)
        data.append(pers_kids)
        data.append(pers_trans)
        print(json.dumps(data, cls=json.JSONEncoder, ensure_ascii=False, indent=4))

        return Response(json.dumps(data, cls=json.JSONEncoder, ensure_ascii=False, indent=4),
                        content_type='application/json', status=status.HTTP_200_OK)

```
