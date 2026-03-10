#flask
#


from flask import Flask, render_template, request, render_template_string
import joblib
import os
from groq import Groq
import sqlite3
import datetime

#from dotenv import load_dotenv
#if os.path.exists('.env'):
#    load_dotenv()

# for AWS, do not run this because not using .env
#os.environ["GROQ_API_KEY"] = ""
#os.environ["GROQ_API_KEY"] = os.environ.get('GROQ_API_KEY')

client = Groq()

app = Flask(__name__)
application = app  # This creates a reference AWS can find easily

# --- NEW: Load Guardrail Model ---
# Ensure compliance_guardrail.pkl is uploaded to AWS with this file
guardrail_model = joblib.load("compliance_guardrail.pkl")

def init_audit_db():
    conn = sqlite3.connect("user.db")
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS audit_log (query TEXT, risk_level TEXT, timestamp TEXT)')
    conn.commit()
    conn.close()

init_audit_db()

@app.route("/",methods=["GET","POST"])
def index():
    return(render_template("index.html"))

@app.route("/main",methods=["GET","POST"])
def main():
    name = request.form.get("q")
    t = datetime.datetime.now()
    conn = sqlite3.connect("user.db")
    c = conn.cursor()
    c.execute('INSERT INTO user (name,timestamp) VALUES(?,?)',(name,t))
    conn.commit()
    c.close()
    conn.close()
    return(render_template("main.html"))

@app.route("/dbs",methods=["GET","POST"])
def dbs():
    return(render_template("dbs.html"))


@app.route("/dbs_prediction",methods=["GET","POST"])
def dbs_prediction():
    q = float(request.form.get("q"))
    model = joblib.load("DBS_SGD_model.pkl")
    r = model.predict([[q]])
    return(render_template("dbs_prediction.html",r=r))

@app.route("/chatbot",methods=["GET","POST"])
def chatbot():
    return(render_template("chatbot.html"))

@app.route("/llama",methods=["GET","POST"])
def llama():
    return(render_template("llama.html"))

@app.route("/llama_result",methods=["GET","POST"])
def llama_result():
    q = request.form.get("q")

# --- NEW: Guardrail Logic ---
    risk_status = guardrail_model.predict([q])[0]
    
    if risk_status == "RISK":
        # Log to the audit table
        t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect("user.db")
        c = conn.cursor()
        c.execute('INSERT INTO audit_log (query, risk_level, timestamp) VALUES(?,?,?)', (q, "HIGH", t))
        conn.commit()
        conn.close()
        return "⚠️ Security Alert: Your query has been flagged for policy violations and logged."


    r = client.chat.completions.create(
    model="llama-3.1-8b-instant",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": q}])
    r = r.choices[0].message.content
    return(render_template("llama_result.html",r=r))

@app.route("/paynow",methods=["GET","POST"])
def paynow():
    return(render_template("paynow.html"))

@app.route("/userlog",methods=["GET","POST"])
def userlog():
    conn = sqlite3.connect("user.db")
    c = conn.cursor()
    c.execute('''select *
    from user''')
    r=""
    for row in c:
        print(row)
        r = r + str(row)
    c.close()
    conn.close()
    return(render_template("userlog.html",r=r))

@app.route("/deletelog",methods=["GET","POST"])
def deletelog():
    conn = sqlite3.connect("user.db")
    c = conn.cursor()
    c.execute('DELETE FROM user',);
    conn.commit()
    c.close()
    conn.close()
    return(render_template("deletelog.html"))

# --- NEW: Security Dashboard for CSO ---
@app.route("/security_dashboard")
def security_dashboard():
    conn = sqlite3.connect("user.db")
    c = conn.cursor()
    c.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 5")
    logs = c.fetchall()
    conn.close()
    
    analysis = "No recent threats."
    if logs:
        # Use AI to summarize the threats
        summary_prompt = f"Summarize these blocked security logs in one sentence: {str(logs)}"
        r = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": summary_prompt}]
        )
        analysis = r.choices[0].message.content

    # Simple inline dashboard
    html = f"""
    <h2>🛡️ Security Dashboard</h2>
    <p><strong>AI Threat Summary:</strong> {analysis}</p>
    <table border="1">
        <tr><th>Timestamp</th><th>Query</th><th>Risk</th></tr>
        {''.join([f"<tr><td>{l[2]}</td><td>{l[0]}</td><td>{l[1]}</td></tr>" for l in logs])}
    </table>
    <br><a href="/">Back to Home</a>
    """
    return render_template_string(html)


if __name__ == "__main__":
    app.run()
