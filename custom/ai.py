from flask import Flask, request, render_template
import os
import openai
import html

def sanitize_input(input_str):
    return html.escape(input_str)

app = Flask(__name__)
openai.api_key = os.getenv("OPENAI_API_KEY")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        text_input = request.form.get("text_input")
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=f"{text_input}",
            temperature=0,
            max_tokens=4000,
            top_p=1.0,
            frequency_penalty=0.0,
            presence_penalty=0.0
            )
        message = response.choices[0]["text"]
        clean = sanitize_input(message)
        return '''
        <html>
            <head>
                <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
                <title>Ask a question</title>
            </head>
            <body>
                <div class="container">
                    <h1 class="text-center mt-5">Ask a question</h1>
                    <form method="post">
                        <div class="form-group">
                            <textarea class="form-control" name="text_input"></textarea>
                        </div>
                        <br></br>
                        <input type="submit" class="btn btn-primary" value="Submit">
                    </form>
                    <h1 class="text-centre mt-5">Answer</h1>
                    <pre class="text-left">
                    {}
                    </pre>
                </div>
            </body>
        </html>
        '''.format(clean)
    return '''
    <html>
        <head>
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
            <title>Ask a question</title>
        </head>
        <body>
            <div class="container">
                <h1 class="text-center mt-5">Ask a question</h1>
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
