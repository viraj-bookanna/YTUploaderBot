import os,json,sqlite3,logging,aiohttp,urllib.parse,time,hashlib,aiofiles,requests
from telethon import TelegramClient,events,Button
from telethon.tl.types import MessageEntityUrl
from dotenv import load_dotenv

load_dotenv(override=True)
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

bot = TelegramClient('bot', os.environ['API_ID'], os.environ['API_HASH']).start(bot_token=os.environ['BOT_TOKEN'])
CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
DOWNLOAD_DIR = os.path.join(os.getcwd(), 'videos')
AUTH_URL = f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={CLIENT_ID}&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fyoutube.upload&prompt=consent&access_type=offline"
CONN = sqlite3.connect('database.db')

if not os.path.isdir(DOWNLOAD_DIR):
    os.makedirs(DOWNLOAD_DIR)

def db_get(key, default=None):
    try:
        cursor = CONN.cursor()
        cursor.execute('SELECT value FROM key_values WHERE key=?', (key,))
        return json.loads(cursor.fetchone()[0])
    except:
        return default
def db_put(key, value):
    cursor = CONN.cursor()
    cursor.execute('''
CREATE TABLE IF NOT EXISTS key_values (
    key CHAR PRIMARY KEY,
    value TEXT
)
''')
    cursor.execute('INSERT OR REPLACE INTO key_values (key, value) VALUES (?, ?)', (key, json.dumps(value)))
    CONN.commit()
def humanify(byte_size):
    siz_list = ['KB', 'MB', 'GB']
    for i in range(len(siz_list)):
        if byte_size/1024**(i+1) < 1024:
            return "{} {}".format(round(byte_size/1024**(i+1), 2), siz_list[i])
def progress_bar(percentage):
    prefix_char = '█'
    suffix_char = '▒'
    progressbar_length = 10
    prefix = round(percentage/progressbar_length) * prefix_char
    suffix = (progressbar_length-round(percentage/progressbar_length)) * suffix_char
    return "{}{} {}%".format(prefix, suffix, percentage)
class TimeKeeper:
    last = 0
    last_edited_time = 0
async def prog_callback(upordown, current, total, event, file_org_name, tk):
    percentage = round(current/total*100, 2)
    if tk.last+2 < percentage and tk.last_edited_time+5 < time.time():
        await event.edit("{}loading {}\nFile Name: {}\nSize: {}\n{}loaded: {}".format(upordown, progress_bar(percentage), file_org_name, humanify(total), upordown, humanify(current)))
        tk.last = percentage
        tk.last_edited_time = time.time()
def seconds_to_human_time(sec): 
    hrs = sec // 3600
    sec %= 3600
    mins = sec // 60
    sec %= 60
    return "%02d:%02d:%02d" % (hrs, mins, sec) 
def parse_header(header):
    header = header.split(';', 1)
    if len(header)==1:
        return header[0].strip(), {}
    params = [p.split('=') for p in header[1].split(';')]
    return header[0].strip(), {key[0].strip(): key[1].strip('" ') for key in params}
async def get_url(session, url, event, custom_filename):
    current = 0
    last = 0
    last_edited_time = 0
    file_org_name = os.path.basename(urllib.parse.urlparse(url).path)
    file_name = ""
    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'sec-ch-ua': '"Microsoft Edge";v="117\', "Not;A=Brand";v="8\', "Chromium";v="117"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1'
    }
    start_time = time.time()
    async with session.get(url, headers=headers, verify_ssl=False) as response:
        server_filename = parse_header(response.headers.get('content-disposition', ''))[1].get('filename', None)
        total = int(response.headers.get('content-length', 0)) or None
        if custom_filename is not None:
            file_org_name = custom_filename
        elif server_filename:
            file_org_name = server_filename
        if len(file_org_name) > 250:
            file_org_name = hashlib.md5(file_org_name.encode()).hexdigest()
        file_name = os.path.join(DOWNLOAD_DIR, file_org_name)
        async with aiofiles.open(file_name, 'wb') as file:
            async for chunk in response.content.iter_chunked(1024):
                await file.write(chunk)
                current += len(chunk)
                percentage = 0 if total is None else round(current/total*100, 2)
                if last+2 < percentage and last_edited_time+5 < time.time():
                    await event.edit("**Downloading**: {}\n**FileName**: {}\n**Size**: {}\n**Downloaded**: {}\n**ElapsedTime**: {}".format(
                        progress_bar(percentage), file_org_name, humanify(total), humanify(current), seconds_to_human_time(time.time()-start_time))
                    )
                    last = percentage
                    last_edited_time = time.time()
    if os.path.isfile(file_name):
        return file_name
    await event.edit("Error\nSomething went wrong ..")
    raise Exception('Something went wrong ..')
async def dl_file(url, event, custom_filename=None):
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False),
        timeout=aiohttp.ClientTimeout(total=60*int(os.environ['DOWNLOAD_TIMEOUT_MINUTES']))
    ) as session:
        return await get_url(session, url, event, custom_filename)
def find_all_urls(message):
    ret = list()
    if message.entities is None:
        return ret
    for entity in message.entities:
        if type(entity) == MessageEntityUrl:
            url = message.text[entity.offset:entity.offset+entity.length]
            if url.startswith('http://') or url.startswith('https://'):
                ret.append(url)
            else:
                ret.append('http://'+url)
    return ret
def authenticate(code):
    data = {
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
        'grant_type': 'authorization_code',
    }
    response = requests.post('https://oauth2.googleapis.com/token', data=data).json()
    if 'error' in response:
        raise Exception(response['error'])
    return response
def getUploadURI(auth, title, description, uploadContentLength):
    jdata = {"snippet":{"title":title,"description":description,"tags":[""]},"status":{"privacyStatus":"private","license":"youtube"}}
    headers = {
        "Authorization": f"Bearer {auth}",
        "X-Upload-Content-Length": str(uploadContentLength),
        "X-Upload-Content-Type": "application/octet-stream",
    }
    response = requests.post('https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status', json=jdata, headers=headers, allow_redirects=False)
    if len(response.content) > 0 and 'error' in response.json():
        raise Exception(response.json()['error'])
    return response.headers['location']
async def file_sender(file_name, callback=None):
    async with aiofiles.open(file_name, 'rb') as f:
        current = 0
        total = os.path.getsize(file_name)
        chunk = await f.read(64*1024)
        while chunk:
            if callback is not None:
                current += len(chunk)
                await callback(current, total)
            yield chunk
            chunk = await f.read(64*1024)
async def uploadVideo(auth, filePath, url, callback):
    headers = {
        "Authorization": f"Bearer {auth}",
        "Content-Type": "application/octet-stream"
    }
    async with aiohttp.ClientSession() as session:
        async with session.put(url, data=file_sender(filePath, callback)) as resp:
            response = await resp.json()
    if 'error' in response:
        raise response['error']
    return response
def refreshToken(refresh_token):
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
    }
    response = requests.post('https://oauth2.googleapis.com/token', data=data).json()
    if 'error' in response:
        raise Exception(response['error'])
    return response
def get_auth(chat_id):
    user_data = db_get(chat_id)
    if user_data is None or 'auth' not in user_data:
        return None
    elif user_data['auth']['expire_time'] < time.time():
        refresh = refreshToken(user_data['auth']['refresh_token'])
        user_data['auth']['access_token'] = refresh['access_token']
        user_data['auth']['expire_time'] = time.time()+refresh['expires_in']
        db_put(chat_id, user_data)
        return user_data['auth']['access_token']
    else:
        return user_data['auth']['access_token']

direct_reply = {
    '/start': 'Hi',
    '/help': 'Send any video file or URL to upload into your YouTube channel\nUse /login to authenticate',
}

async def all_handler(event):
    urls = find_all_urls(event.message)
    user_data = db_get(event.chat_id, {})
    file = None
    if len(urls)==1:
        msg = await event.respond('wait...')
        file = await dl_file(urls[0], msg)
    elif event.message.media is not None and 'video/' in event.message.file.mime_type:
        msg = await event.respond('wait...')
        tk = TimeKeeper()
        file = await event.message.download_media(DOWNLOAD_DIR, progress_callback=lambda c,t:prog_callback('Down',c,t,msg,event.message.file.name,tk))
    elif event.message.text in direct_reply.keys():
        await event.respond(direct_reply[event.message.text])
    elif event.message.text=='/login':
        db_put(event.chat_id, {'next': 'login'})
        await event.respond(f'Open this [LINK]({AUTH_URL}) and send me the given code to authenticate')
    elif user_data.get('next', '')=='login':
        try:
            user_data['auth'] = authenticate(event.message.text)
            user_data['auth']['expire_time'] = time.time()+user_data['auth']['expires_in']
            await event.respond('Login successful')
            db_put(event.chat_id, user_data)
        except Exception as e:
            await event.respond(repr(e))
    else:
        await event.respond('unknown command')
    if file is not None:
        auth = get_auth(event.chat_id)
        filename = os.path.basename(file)
        upload_url = getUploadURI(
            auth,
            filename,
            'event.message.text' if event.message.text is None else event.message.text,
            os.path.getsize(file)
        )
        tk = TimeKeeper()
        response = await uploadVideo(auth, file, upload_url, lambda c,t:prog_callback('Up',c,t,msg,filename,tk))
        await msg.edit(f'Successfully uploaded to YouTube\nTitle: {filename}', buttons=[[Button.url('Open YouTube', f'https://youtu.be/{response["id"]}')]])

@bot.on(events.NewMessage())
async def handler(event):
    try:
        await all_handler(event)
    except Exception as e:
        await event.respond(repr(e))

with bot:
    bot.run_until_disconnected()