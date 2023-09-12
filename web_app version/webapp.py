from flask import Flask, render_template, request, send_from_directory
import os
import random
from generator import generator

gen = random.randint(1, 1000)

app = Flask(__name__)
UPLOAD_FOLDER = './input'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route("/")
def generation():
    return render_template('generation.html', title="Welcome to Rapport Generator")


@app.route("/download", methods=["POST"])
def download():
    society_name = request.form.get("society_name")

    # get the csv file anf its path
    csv_file = request.files["csv_file"]
    filename, extension = os.path.splitext(csv_file.filename)
    update_csvname = f"{filename}_{gen}{extension}"
    csv_path = os.path.join(app.config['UPLOAD_FOLDER'], update_csvname)
    csv_file.save(csv_path)

    # get the society's logo and its path
    default_logo_path = "./static/defaultlogo.png"
    society_file = request.files["society_logo"]
    if society_file:
        filename, extension = os.path.splitext(society_file.filename)
        update_logoname = f"{filename}_{gen}{extension}"
        logo_path = os.path.join(app.config['UPLOAD_FOLDER'], update_logoname)
        society_file.save(logo_path)
    else:
        logo_path = default_logo_path

    # generate the rapport
    generated_rapport = generator(csv_path, society_name, logo_path, gen)

    # after generation
    os.remove(csv_path)
    if logo_path != default_logo_path:
        os.remove(logo_path)

    return render_template('download.html', title="Download the Rapport", generated_rapport=generated_rapport)


@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory('./rapports', filename)


if __name__ == '__main__':
    app.run(debug=True)
