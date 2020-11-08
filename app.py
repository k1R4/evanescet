import simplejson as json
import base64
from passlib.hash import pbkdf2_sha256
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET'])
def encrypt():
    args = request.query_string.decode()
    if args == "":
        return render_template('index.html', err='Please fill all the fields')
    args = args.split('=')
    url = args[1].split('&')[0]
    txt = args[2].split('&')[0]
    password = args[3]
    if not url.isalnum():
        return render_template('index.html', err='Only alphanumeric url is allowed')
    if txt == "" or url == "" or password == "":
        return render_template('index.html', err='Please fill all the fields')
    
    with open('text.json', 'r+') as f:
        text = json.load(f)
        if url in text.keys():
           return render_template('index.html', err='That URL is already taken')
        
        hash_pass = pbkdf2_sha256.hash(password)
        encryptext = base64.b64encode(str.encode(txt)).decode('utf-8')
        
        text[url] = []
        text[url].append(hash_pass)
        text[url].append(encryptext)
        
        f.seek(0)
        json.dump(text, f, indent=4)
        f.truncate()
        return render_template('index.html', inf='Success! Use url to retrieve text')

@app.route('/decrypt/<url>/', methods=['GET'])
def decrypt(url):
    with open('text.json', 'r+') as f:
        if request.query_string == "":
            return render_template('index.html', err='Please enter a valid URL')
        text = json.load(f)
        if url not in text.keys():
            return render_template('index.html', err='That URL doesn\'t exist')
        args = request.query_string.decode()
        if args == "":
            return render_template('index.html', err='Please enter a valid URL')
        args = args.split('=')
        password = args[1]
        if password == "":
           return render_template('index.html', err='Please enter a valid password')
        if not pbkdf2_sha256.verify(password, text[url][0]):
            return render_template('index.html', err='Incorrect password!')
        resp = base64.b64decode(str.encode(text[url][1])).decode('utf-8')
        text.pop(url, None)
        f.seek(0)
        json.dump(text, f, indent=4)
        f.truncate()
        return render_template('decrypted.html', value=resp.replace('+', ' '))

@app.route('/<url>')
def prompt(url):
    with open('text.json', 'r') as f:
        text = json.load(f)
        if url not in text.keys():
            return render_template('index.html', err='That URL doesn\'t exist')
        return render_template('pswd_form.html', value=url) 

if __name__ == "__main__":
    app.run(debug=True)

