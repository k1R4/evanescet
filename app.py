import simplejson as json
import base64
from hashlib import sha256
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
app = Flask(__name__)

# This webapp uses the flask library for managing backend
# It also uses Jinja web template engine to make html code simpler
# Here text.json is used as a simple DB
# sha256 is used to hash password & vigenere cipher is used to encode the text


def enc(plaintext, key): # Custom implementation of vigenere encode
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]
    ciphertext = ''
    for i in range(len(plaintext_int)):
        value = (plaintext_int[i] + key_as_int[i % key_length]) #% 26
        ciphertext += '{}'.format(hex(value))
    ciphertext = ciphertext.replace('0x','')
    return ciphertext


def dec(ciphertext, key): # Custom implementation of vigenere decode
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    ciphertext = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    ciphertext_int = [int(i,base=16) for i in ciphertext]
    plaintext = ''
    for i in range(len(ciphertext_int)):
        value = (ciphertext_int[i] - key_as_int[i % key_length]) #% 26
        plaintext += chr(value)
    return plaintext


@app.route('/') # To render index.html 
def index():
    return render_template('index.html')


@app.route('/encrypt', methods=['GET']) # To handle encrypt requests
def encrypt():
    args = request.query_string.decode()
    if args == "":
        return render_template('index.html', err='Please fill all the fields') # Show err if request headers are empty
    
    url = request.args.get("url")
    password = request.args.get("pass")
    txt = request.args.get("txt")
    
    if not url.isalnum():
        return render_template('index.html', err='Only alphanumeric url is allowed') # Show err if sub-directory isn't alphanumeric
    if txt == "" or url == "" or password == "":
        return render_template('index.html', err='Please fill all the fields') # Show err if fields are empty
    if len(password) > len(txt):
        return render_template('index.html', err='Password is too large') 

    with open('text.json', 'r+') as f: # Opening text.json which is used as DB
        text = json.load(f)
        if url in text.keys():
           return render_template('index.html', err='That URL is already taken') # Show err if sub-directory is already taken
        
        hash_pass = sha256(password.encode('utf-8')).hexdigest() # hashing password
        encryptext = enc(txt,password) # encrypting text

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
        password = request.args.get("pass")
        if password == "":
           return render_template('index.html', err='Please enter a valid password') # Show err if password is empty
        if sha256(password.encode('utf-8')).hexdigest() != text[url][0]:
            return render_template('index.html', err='Incorrect password!') # Show err is password is incorrect
        resp = dec(text[url][1],password)
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