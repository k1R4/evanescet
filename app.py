import simplejson as json
import base64
from passlib.hash import pbkdf2_sha256
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
app = Flask(__name__)

# This webapp uses the flask library for managing backend
# It also uses Jinja web template engine to make html code simpler
# Here text.json is used as a simple DB
# PBKDF2 is used to hash password & base64 is used to encode the text

@app.route('/') # To render index.html 
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET']) # To handle encrypt requests
def encrypt():
    args = request.query_string.decode()
    if args == "":
        return render_template('index.html', err='Please fill all the fields') # Show err if request headers are empty
    args = args.split('=')
    url = args[1].split('&')[0]
    password = args[2].split('&')[0]
    txt = args[3]
    if not url.isalnum():
        return render_template('index.html', err='Only alphanumeric url is allowed') # Show err if sub-directory isn't alphanumeric
    if txt == "" or url == "" or password == "":
        return render_template('index.html', err='Please fill all the fields') # Show err if fields are empty
    
    with open('text.json', 'r+') as f: # Opening text.json which is used as DB
        text = json.load(f)
        if url in text.keys():
           return render_template('index.html', err='That URL is already taken') # Show err if sub-directory is already taken
        
        hash_pass = pbkdf2_sha256.hash(password) # hashing password
        encryptext = base64.b64encode(str.encode(txt)).decode('utf-8') # encrypting text
        
        text[url] = []
        text[url].append(hash_pass)
        text[url].append(encryptext)
        
        f.seek(0)
        json.dump(text, f, indent=4) # save info to DB
        f.truncate()
        return render_template('index.html', inf='Success! Use url to retrieve text') # Show success message

@app.route('/decrypt/<url>/', methods=['GET']) # To handle decrypt requests
def decrypt(url):
    with open('text.json', 'r+') as f:
        if request.query_string == "":
            return render_template('index.html', err='Please enter a valid URL') # Show err if request headers are empty
        text = json.load(f)
        if url not in text.keys():
            return render_template('index.html', err='That URL doesn\'t exist') # Show err if sub-directory doesn't exist in DB
        args = request.query_string.decode()
        if args == "":
            return render_template('index.html', err='Please enter a valid URL') # Show err if requested url is empty
        args = args.split('=')
        password = args[1]
        if password == "":
           return render_template('index.html', err='Please enter a valid password') # Show err if password is empty
        if not pbkdf2_sha256.verify(password, text[url][0]):
            return render_template('index.html', err='Incorrect password!') # Show err is password is incorrect
        resp = base64.b64decode(str.encode(text[url][1])).decode('utf-8')
        text.pop(url, None)
        f.seek(0)
        json.dump(text, f, indent=4) # Remove info from DB
        f.truncate()
        return render_template('decrypted.html', value=resp.replace('+', ' '))

@app.route('/<url>') # To render password form for decrypting text
def prompt(url):
    with open('text.json', 'r') as f:
        text = json.load(f)
        if url not in text.keys():
            return render_template('index.html', err='That URL doesn\'t exist') # Show err if sub-directory doesn't exist in DB
        return render_template('pswd_form.html', value=url) 

if __name__ == "__main__":
    app.run(debug=True) # Enable debugging and logs since app is not a production version

