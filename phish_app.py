from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
        <h2>Fake Login</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
    ''')

@app.route('/login', methods=['POST'])
def login():
    # Just show a phishing warning message, don't actually collect data
    return "<h3>This was a phishing test page. Don't enter real credentials!</h3>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000) 