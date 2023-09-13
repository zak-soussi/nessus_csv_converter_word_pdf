import os, sys, random
import shutil

from generator import generator

society_name = None
image_path = None
csv_path = None

sys.argv = sys.argv[1:]
number_of_arguments = len(sys.argv)

if number_of_arguments < 2:
    print("You have to provide at least the society's name and the csv file name")
elif number_of_arguments > 3:
    print("You have to provide the society's name , one csv file name and the name of the society's logo picture ")

else:
    csv_count = 0
    remaining_args = []
    for arg in sys.argv:
        if ".csv" in arg:
            csv_count += 1
            csv_path = f"./{arg}"
        else:
            remaining_args.append(arg)
    if not csv_count:
        print("You must provide a csv file")
    elif csv_count > 1:
        print("You have to provide only one csv file")
    else:
        picture_extension = [".png", ".jpg", ".jpeg"]
        name_count = 0
        for arg in remaining_args:
            check = True
            for extension in picture_extension:
                if extension in arg:
                    check = False
                    break
            if check:
                name_count += 1
                society_name = arg
            else:
                image_path = f"./{arg}"
        if not name_count:
            print("You must provide the society's name")
        elif name_count > 1:
            print("You have to provide only one society name")
        else:
            gen = random.randint(1, 2000)
            # create the folder that will contain all the necessary files to generate the rapport
            UPLOAD_FOLDER = f'./files_to_use/rapport_{gen}'
            os.mkdir(UPLOAD_FOLDER)
            generator(csv_path, society_name, image_path, UPLOAD_FOLDER, gen)
            shutil.rmtree(UPLOAD_FOLDER)
            print("The rapport has been generated successfully , you can find it in the rapports folder")
