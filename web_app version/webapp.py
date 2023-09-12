from flask import Flask, render_template, request, send_from_directory
import os
import random
from generator import generator
import shutil

gen = random.randint(1, 2000)

app = Flask(__name__)


@app.route("/")
def generation():
    return render_template('generation.html', title="Welcome to Rapport Generator")


@app.route("/download", methods=["POST"])
def download():
    #create the folder that will contain all the necessary files to generate the rapport
    UPLOAD_FOLDER = f'./files_to_use/rapport_{gen}'
    os.mkdir(UPLOAD_FOLDER)


    society_name = request.form.get("society_name")

    # get the csv file anf its path
    csv_file = request.files["csv_file"]
    csv_path = os.path.join(UPLOAD_FOLDER, csv_file.filename)
    csv_file.save(csv_path)

    # get the society's logo and its path
    default_logo_path = "./static/defaultlogo.png"
    society_file = request.files["society_logo"]
    if society_file:
        logo_path = os.path.join(UPLOAD_FOLDER, society_file.filename)
        society_file.save(logo_path)
    else:
        logo_path = default_logo_path

    # generate the rapport
    generated_rapport = generator(csv_path, society_name, logo_path, UPLOAD_FOLDER , gen)

    # after generation
    shutil.rmtree(UPLOAD_FOLDER)

    return render_template('download.html', title="Download the Rapport", generated_rapport=generated_rapport)


@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory('./rapports', filename)


if __name__ == '__main__':
    app.run(debug=True)
