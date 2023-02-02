from flask import Flask, request, render_template
import os
import html
from datetime import datetime


def sanitize_input(input_str):
    return html.escape(input_str)


def get_timestamp():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return timestamp

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        text_input = request.form.get("text_input")
        clean = sanitize_input(text_input)
        with open("log.txt", "a") as f:
            f.write("[+] " + get_timestamp() + "\n")
            f.write(clean + "\n")
        return '''
        <html>
            <head>
                <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
                <title>Logger</title>
            </head>
            <body>
                <div class="container">
                    <h1 class="text-center mt-5">Add a log entry</h1>
                    <form method="post">
                        <div class="form-group">
                            <textarea class="form-control" name="text_input"></textarea>
                        </div>
                        <br></br>
                        <input type="submit" class="btn btn-primary" value="Submit">
                    </form>
                    <h1 class="text-centre mt-5">Answer</h1>
                    <code class="text-left">
                    {}
                    </code>
                </div>
            </body>
        </html>
        '''.format(clean)
    return '''
    <html>
        <head>
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
            <title>Add a log entry</title>
        </head>
        <body>
            <div class="container">
                <h1 class="text-center mt-5">Add a log entry</h1>
                <form method="post">
                    <div class="form-group">
                        <textarea class="form-control" name="text_input"></textarea>
                    </div>
                    <br></br>
                    <input type="submit" class="btn btn-primary" value="Submit">
                </form>
            </div>
        </body>
    </html>
    '''

if __name__ == "__main__":
    app.run(debug=False)
