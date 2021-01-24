#!/usr/bin/env python
import os,re,requests
import hashlib

def make_dir(dirname):
    if not os.path.exists(dirname):
        os.mkdir(dirname)

base_images_dirname = "./images"
make_dir(base_images_dirname)
file_names = os.listdir("./")
url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+/upload_images/\w{8}-\w{16}.\w{3}\?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240"
image_pattern = r"\w{8}-\w{16}.\w{3}"
for name in file_names:
    if os.path.isfile(name):
        data = open(name,"rb").read()
        image_urls = re.findall(url_pattern,data)
        sub_images_dirname = base_images_dirname + "/" + hashlib.md5(name.replace(".md","")).hexdigest().lower()
        
        if image_urls != []:
            make_dir(sub_images_dirname)

        for image_url in image_urls:
            image_name = re.findall(image_pattern,image_url)[0]
            r = requests.get(image_url)
            image_name = sub_images_dirname + "/" + image_name
            open(image_name,"wb").write(r.content)
            data = data.replace(image_url,image_name[1:])

        open(name,"wb").write(data)
