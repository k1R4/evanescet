import simplejson as json
from hashlib import sha256
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
app = Flask(__name__)

# This webapp uses the flask library for managing backend
# It also uses Jinja web template engine to make html code simpler
# Here text.json is used as a simple DB
# sha256 is used to hash password & vigenere cipher is used to encode the text


# Custom implementation of vigenere encode
def enc(plaintext, key): 
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]
    ciphertext = ''
    
    for i in range(len(plaintext_int)):
        value = (plaintext_int[i] + key_as_int[i % key_length])
        ciphertext += '{}'.format(hex(value))
    
    ciphertext = ciphertext.replace('0x','')
    return ciphertext


# Custom implementation of vigenere decode
def dec(ciphertext, key): 
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    ciphertext = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    ciphertext_int = [int(i,base=16) for i in ciphertext]
    plaintext = ''
    
    for i in range(len(ciphertext_int)):
        value = (ciphertext_int[i] - key_as_int[i % key_length])
        plaintext += chr(value)
    
    return plaintext


# To render index.html 
@app.route('/') 
def index():
    return render_template('index.html')


# To handle encrypt requests
@app.route('/encrypt', methods=['GET'])
def encrypt():
    args = request.query_string.decode()
    if args == "":
        # Show error if request headers are empty
        return render_template('index.html', err='Please fill all the fields') 
    
    url = request.args.get("url")
    password = request.args.get("pass")
    txt = request.args.get("txt")
    
    if not url.isalnum():
        # Show error if sub-directory isn't alphanumeric
        return render_template('index.html', err='Only alphanumeric url is allowed') 
    
    if txt == "" or url == "" or password == "":
        # Show error if fields are empty
        return render_template('index.html', err='Please fill all the fields') 
    
    if len(password) > len(txt):
        # Show error if password size is larger than text
        return render_template('index.html', err='Password is too large') 

    # Opening text.json which is used as DB
    with open('text.json', 'r+') as f: 
        text = json.load(f)
        if url in text.keys():
           # Show error if sub-directory is already taken
           return render_template('index.html', err='That URL is already taken') 
        
        # hashing password
        hash_pass = sha256(password.encode('utf-8')).hexdigest() 
        # encrypting text
        encryptext = enc(txt,password) 

        text[url] = []
        text[url].append(hash_pass)
        text[url].append(encryptext)
        
        f.seek(0)
        # save info to DB
        json.dump(text, f, indent=4) 
        f.truncate()

        # Show success message
        return render_template('index.html', inf='Success! Use url to retrieve text') 


# To handle decrypt requests
@app.route('/decrypt/<url>/', methods=['GET']) 
def decrypt(url):
    with open('text.json', 'r+') as f:
        if request.query_string == "":
            # Show error if request headers are empty
            return render_template('index.html', err='Please enter a valid URL') 
        text = json.load(f)
        if url not in text.keys():
            # Show error if url doesn't exist in DB
            return render_template('index.html', err='That URL doesn\'t exist') 
        args = request.query_string.decode()
        if args == "":
            # Show error if requested url is empty
            return render_template('index.html', err='Please enter a valid URL') 
        password = request.args.get("pass")
        if password == "":
            # Show error if password is empty
           return render_template('index.html', err='Please enter a valid password') 
        if sha256(password.encode('utf-8')).hexdigest() != text[url][0]:
            return render_template('index.html', err='Incorrect password!') # Show err is password is incorrect
        resp = dec(text[url][1],password)
        text.pop(url, None)
        f.seek(0)
        # Remove info from DB
        json.dump(text, f, indent=4) 
        f.truncate()
        return render_template('decrypted.html', value=resp.replace('+', ' '))


# To render password form for decrypting text
@app.route('/<url>') 
def prompt(url):
    with open('text.json', 'r') as f:
        text = json.load(f)
        if url not in text.keys():
            # Show error if url doesn't exist in DB
            return render_template('index.html', err='That URL doesn\'t exist') 
        return render_template('pswd_form.html', value=url) 


if __name__ == "__main__":
    # Enable debugging and logs since app is not a production version
    app.run(debug=True) 