import simplejson as json
import base64
from passlib.hash import pbkdf2_sha256
from flask import Flask, render_template, request, redirect
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET'])
def encrypt():
    args = request.query_string.decode('utf-8')
    if args == "":
        return redirect('/')
    args = args.split('=')
    txt = args[1].split('&')[0]
    url = args[2].split('&')[0]
    password = args[3]

    if txt == "" or url == "" or password == "":
        return redirect('/')
    
    with open('text.json', 'r+') as f:
        text = json.load(f)
        if url in text.keys():
           return redirect('/')
        
        hash_pass = pbkdf2_sha256.hash(password)
        encryptext = base64.b64encode(str.encode(txt)).decode('utf-8')
        
        text[url] = []
        text[url].append(hash_pass)
        text[url].append(encryptext)
        
        f.seek(0)
        json.dump(text, f, indent=4)
        f.truncate()
        return redirect('/')

@app.route('/decrypt/<url>/', methods=['GET'])
def decrypt(url):
    with open('text.json', 'r+') as f:
        if request.query_string == "":
            return redirect('/')
        text = json.load(f)
        if url not in text.keys():
            return redirect('/')
        args = request.query_string.decode('utf-8')
        if args == "":
            return redirect('/')
        args = args.split('=')
        password = args[1]
        
        if password == "":
           return redirect('/')
        if not pbkdf2_sha256.verify(password, text[url][0]):
            return redirect('/')
        resp = base64.b64decode(str.encode(text[url][1])).decode('utf-8')
        text.pop(url, None)
        f.seek(0)
        json.dump(text, f, indent=4)
        f.truncate()
        return resp.replace('+', ' ')

@app.route('/<url>')
def prompt(url):
    with open('text.json', 'r') as f:
        text = json.load(f)
        if url not in text.keys():
            return redirect('/')
        return render_template('pswd_form.html', value=url) 

if __name__ == "__main__":
    app.run(debug=True)

