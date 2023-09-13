import shutil
from tkinter import *
from tkinter import filedialog
from PIL import Image, ImageTk
from generator import generator
import random, os

image_path = None
csv_path = None


def open_image():
    global image_path
    image_path = filedialog.askopenfilename(initialdir=".", title="Select The society's logo",
                                            filetypes=[("Image files", "*.png *.jpg *.jpeg")])
    if image_path:
        img = Image.open(image_path)
        img.thumbnail((100, 100))
        image_preview = ImageTk.PhotoImage(img)
        image_label.config(image=image_preview)
        image_label.image = image_preview


def open_csv():
    global csv_path
    csv_path = filedialog.askopenfilename(initialdir=".", title="Select a csv File", filetypes=[("CSV files", "*.csv")])
    if csv_path:
        csv_entry.configure(state="normal")
        csv_entry.delete(0, END)
        csv_entry.insert(0, csv_path)
        csv_entry.configure(state="readonly")


def just_wait(window):
    waiting_label = Label(window, text="Please keep waiting...", font=("Helvetica", 12))
    waiting_label.pack(pady=10)


def submit_form():
    global csv_path
    global image_path
    society_name = name_entry.get()

    if society_name and csv_path:

        gen = random.randint(1, 2000)
        # create the folder that will contain all the necessary files to generate the rapport
        UPLOAD_FOLDER = f'./files_to_use/rapport_{gen}'
        os.mkdir(UPLOAD_FOLDER)

        # Create the generation window
        generation_window = Toplevel(root)
        generation_window.title("Generation in progress")
        generation_window.geometry("400x200")
        root.withdraw()

        # Display message
        clarification_label = Label(generation_window,
                                    text="This window will close automatically once the report has been generated",
                                    font=("Helvetica", 12))
        clarification_label.pack(pady=30)

        generation_window.after(10000, lambda: just_wait(generation_window))
        # Generation
        generator(csv_path, society_name, image_path , UPLOAD_FOLDER , gen)

        # End of generation
        shutil.rmtree(UPLOAD_FOLDER)
        required_fields.config(fg="black")
        csv_path = None
        csv_entry.configure(state="normal")
        csv_entry.delete(0, END)
        csv_entry.configure(state="readonly")
        name_entry.delete(0, END)
        root.deiconify()
        generation_window.destroy()

    else:
        required_fields.config(fg="red")


root = Tk()
root.title("Welcome to Nessus Rapport Generator")
root.geometry("600x450")

# Name Field
name_label = Label(root, text="Enter the society's name", font=("Helvetica", 14))
name_label.pack(pady=10)
name_entry = Entry(root, font=("Helvetica", 12))
name_entry.pack(pady=5)

# Image field
image_label = Label(root, text="Society's Logo Preview", font=("Helvetica", 14))
image_label.pack(pady=10)
select_image_button = Button(root, text="Select Image", command=open_image, font=("Helvetica", 12))
select_image_button.pack()

# CSV field
csv_label = Label(root, text="Enter the CSV file path", font=("Helvetica", 14))
csv_label.pack(pady=10)
csv_entry = Entry(root, state="readonly", font=("Helvetica", 12))
csv_entry.pack(pady=5, fill=X)
select_csv_button = Button(root, text="Select CSV", command=open_csv, font=("Helvetica", 12))
select_csv_button.pack()

# Convert Button
convert_button = Button(root, text="CONVERT", command=submit_form, font=("Helvetica", 16), bg="green", fg="white")
convert_button.pack(pady=20)

# Insufficient Input Warning
required_fields = Label(root, text="Both the society's name and the CSV file are required", font=("Helvetica", 12))
required_fields.pack()

root.mainloop()
