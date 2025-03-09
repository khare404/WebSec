from flask import Flask, render_template, request
from vulnerabilities.sql_injection import scan  # Import the scan function from sql_injection module
from vulnerabilities.xss import scan as scan_xss
from vulnerabilities.enum import enumerate_target
from vulnerabilities.misconfig import scan_misconfig


app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    target = None
    module = None

    if request.method == "POST":
        target = request.form.get("target")
        module = request.form.get("module")

        # Check which module to run
        if module == "sql":
            result = scan(target)  # Use the imported scan function
        elif module == "xss":
            result = scan_xss(target)
        elif module == "enum":
            result = enumerate_target(target)
        elif module == "misconfig":
            result = scan_misconfig(target)

        else:
            result = f"Simulated scan on target: {target} using module: {module}"

    return render_template("index.html", result=result, target=target, module=module)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

if __name__ == "__main__":
    app.run(debug=True)
