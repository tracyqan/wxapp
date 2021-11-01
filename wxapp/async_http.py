import re
import socketio
import asyncio
from datetime import datetime
import traceback
import time
import json
import aiohttp
from aiohttp.client_exceptions import ClientConnectionError
from sanic import Sanic
import sys
from engineio.payload import Payload

from aiosocksy import Socks5Auth
from aiosocksy.connector import ProxyConnector, ProxyClientRequest

import base64
from Crypto.Cipher import AES

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

sys.dont_write_bytecode = True
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

clients = {}
socket = socketio.AsyncServer(async_mode='sanic', cors_allowed_origins='*')
app = Sanic(name='AsyncHttp')
socket.attach(app)
time_format = '%Y-%m-%d %H:%M:%S.%f'
Payload.max_decode_packets = 500

KEY = 'Vzq2AnAy8sjakBxBr02hQBlwvyghi93D'
IV = '8822093248871785'
unpad = lambda s: s[:-ord(s[len(s) - 1:])]



def decrypt(data):
    cipher = AES.new(KEY.encode(), AES.MODE_CBC, IV.encode())
    x = cipher.decrypt(base64.urlsafe_b64decode(data))
    r = unpad(x.decode())
    return json.loads(r)


@socket.event
async def connect(sid, environ):
    # pass
    print('Client Connect: ', sid)
    # clients[sid] = aiohttp.ClientSession(trust_env=True)


@socket.event
async def disconnect(sid):
    # pass
    print('disconnect ', sid)
    # await asyncio.sleep(1)
    # await clients[sid].close()
    # clients.pop(sid)


@socket.on('orderPublic')
async def receive(sid, data):
    # print(data)
    # print('======================', type(data))
    decrypt_data = decrypt(data)
    await request(socket, sid, **decrypt_data)


async def request(socket, sid, method='get', url='', body=None, headers=None, text=None,
                  agentip=None, timer=None, mm=None, uuid=None, **kwargs):
    proxy = None
    auth = kwargs.get('auth') or None
    client_session = aiohttp.ClientSession(trust_env=True)
    try:
        host, port = agentip.split(':')
        if port == '1080':
            proxy = f'socks5://{agentip}'
            connector = ProxyConnector()
            client_session = aiohttp.ClientSession(trust_env=True, connector=connector,
                                                   request_class=ProxyClientRequest)
            auth = Socks5Auth(login='guest', password='qaz147wsx')
        else:
            if auth:
                login, pwd = auth.split('|')
                auth = aiohttp.BasicAuth(login=login, password=pwd)
            proxy = f'http://{agentip}'
    except (ValueError, AttributeError):
        pass
    allow_redirects = not kwargs.get('nojump', False)
    data = None
    json_data = None
    result = {'code': 1, 'data': '', 'startTime': '', 'endTime': '', 'processTime': '', 'cookie': ''}
    if 'application/json' in headers.get('Content-Type', ''):
        json_data = body
    else:
        data = body
    if text:
        json_data = None
        data = text.encode()
    try:
        if timer:
            time_stamp = datetime.strptime(f'{timer}.{mm}', time_format) - datetime.now()
            timedelta = time_stamp.total_seconds()
            # before = datetime.now()
            if timedelta > 0:
                await asyncio.sleep(round(timedelta, 4))
            # end = datetime.now()
            # delta = end - before
            # print(f'========{mm}=========')
            # print(
            #     f"Before {before.strftime(time_format)[:-3]}\nEnd {end.strftime(time_format)[:-3]}\nDelta {timedelta - delta.total_seconds()}")
    except:
        traceback.print_exc()
        pass
    # session = clients[sid]

    async with client_session as session:
        start_time = datetime.now()
        result['startTime'] = start_time.strftime(time_format)[:-3]
        try:
            async with session.request(method, url=url, headers=headers, data=data, json=json_data, proxy_auth=auth,
                                       proxy=proxy, allow_redirects=allow_redirects, verify_ssl=False,
                                       timeout=10) as response:
                try:
                    text = await response.text()
                    result['data'] = json.loads(text)
                except UnicodeDecodeError:
                    result['data'] = base64.b64encode(await response.read()).decode()
                except:
                    result['data'] = await response.text()

                result['cookie'] = response.headers.getall('Set-Cookie', [])
        except Exception as e:
            traceback.print_exc()
            result['code'] = 0
            result['data'] = f'{e.__class__.__name__} {e}'
        end_time = datetime.now()
        result['endTime'] = end_time.strftime(time_format)[:-3]
        process_time = end_time - start_time
        result['processTime'] = int(process_time.total_seconds() * 1000)
    if url.startswith('https://wq.jd.com/deal/confirmorder/main'):
        traceId = re.findall('"traceId":"(.*?)"', text)
        traceId = traceId[0] if traceId else ''
        errId = re.findall('"errId":"(.*?)"', text)
        errId = errId[0] if errId else ''
        usedJdBean = re.findall('"usedJdBean":"(.*?)"', text)
        usedJdBean = usedJdBean[0] if usedJdBean else ''
        errMsg = re.findall('"errMsg":"(.*?)"', text)
        errMsg = errMsg[0] if errMsg else ''
        result['data'] = {'traceId': traceId, 'errId': errId, 'usedJdBean': usedJdBean, 'errMsg': errMsg}
        # deal_data = re.findall('window.dealData = (.*?)// traceid', text, re.DOTALL)
        # if not deal_data:
        #     result['data'] = {}
        # else:
        #     deal_data = re.sub('\s', '', deal_data[0])
        #     result['data'] = eval(deal_data)
    # print(result['data'])
    event = uuid or 'orderPublic'
    # print(f'send to {event} ==> ', str(result)[:100])
    await socket.emit(event, data=result, to=sid)



@socket.on('rsaPublic')
async def rsa_encrypt(sid, data):
    decrypt_data = decrypt(data)
    modulus = decrypt_data.get('n')
    exponent = decrypt_data.get('e')
    uuid = decrypt_data['uuid']
    modulus = int(modulus, 16)
    key = rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem = pem.decode().replace('\n', '')
    await socket.emit(uuid, data=pem, to=sid)


@app.get('/close')
def close_api(request):
    app.stop()


async def fetch(session, url):
    async with session.get(url, timeout=2) as response:
        return await response.text()


async def close():
    async with aiohttp.ClientSession() as session:
        try:
            html = await fetch(session, "http://127.0.0.1:3001/close")
        except ClientConnectionError:
            print('服务未启动')
        else:
            print('服务已关闭')


def main():
    port = 3001
    app.run(host='0.0.0.0', port=port)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='并发请求脚本命令')
    parser.add_argument(
        '--close', '-c',
        action='store_true',
        help='关闭服务'
    )
    args = parser.parse_args()
    if not args.close:
        main()
    else:
        asyncio.run(close())
