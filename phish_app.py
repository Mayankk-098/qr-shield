from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
        <div style="max-width:400px;margin:60px auto;padding:2rem;border-radius:1rem;box-shadow:0 4px 32px rgba(0,0,0,0.08);background:#fff;">
            <h2 style="color:#2d3748;text-align:center;margin-bottom:1.5rem;">Secure Bank Login</h2>
            <form method="POST" action="/login">
                <div class="mb-3">
                    <label>Account Number</label>
                    <input type="text" name="username" class="form-control" placeholder="Enter your account number" required>
                </div>
                <div class="mb-3">
                    <label>Password</label>
                    <input type="password" name="password" class="form-control" placeholder="Enter your password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Login</button>
            </form>
            <p style="margin-top:1rem;color:#888;font-size:0.95rem;text-align:center;">© 2024 Secure Bank</p>
        </div>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css">
    ''')

@app.route('/login', methods=['POST'])
def login():
    # Just show a phishing warning message, don't actually collect data
    return "<h3 style='color:red;text-align:center;margin-top:3rem;'>This was a phishing test page. Don't enter real credentials!</h3>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000) 