import os
from flask import Flask, render_template, request, send_file
from tools.sha256 import sha256
import tools.utils as utils
from zipfile import ZipFile
import re


def genKey():
    p = 0
    q = 0
    while (p == q):
        p = utils.genPrimeRange(10**100, 10**101)
        q = utils.genPrimeRange(10**100, 10**101)
    n = p * q
    totient = (p - 1) * (q - 1)
    e = utils.genE(totient)
    d = utils.multi_inverse(e, totient)
    return e, d, n


app = Flask(__name__,
            static_url_path='',
            static_folder='static',
            template_folder='templates')

attc = ""


@app.route('/')
def home():
    if (os.path.isfile(attc)):
        os.remove(attc)
    return render_template('index.html')


@app.route("/generate-key", methods=["POST"])
def generateKey():
    global attc
    e, d, n = genKey()
    req = request.form
    pub_name = str(req["pub"]) + ".pub"
    pri_name = str(req["pri"]) + ".pri"
    f = open(pub_name, "wt")
    f.write(str(e) + ", " + str(n))
    f.close()
    f = open(pri_name, "wt")
    f.write(str(d) + ", " + str(n))
    f.close()
    attc = "keysDS.zip"
    zipObj = ZipFile(attc, 'w')
    zipObj.write(pub_name)
    zipObj.write(pri_name)
    zipObj.close()
    return render_template('index.html', output="Key Generated! Click Download...")


@app.route("/generate-sign", methods=["POST"])
def generateSign():
    global attc
    out = ""
    req = request.form
    f = request.files
    textfile = f["file"]
    pub_file = f["pubfile"]
    if textfile.filename != '':
        textfile.save(textfile.filename)
    if pub_file.filename != '':
        pub_file.save(pub_file.filename)
    if textfile.filename == '':
        m = req["text"]
        md = sha256(m)
        pub = open(pub_file.filename, "rt")
        strpubk = pub.read()
        temp = [int(x) for x in strpubk.split(',')]
        e, n = temp[0], temp[1]
        pub.close()
        s = hex(pow(int(md, 16), e, n))[2:]
        if (req["outStyle"] == "intext"):
            attc = "signedDoc.txt"
            out = m + "\n" + "<ds>" + str(s) + "</ds>"
            fs = open(attc, "w")
            fs.write(out)
            fs.close()
        else:
            attc = "signedDoc.zip"
            fdoc = open("document.txt", "w")
            fdoc.write(m)
            fdoc.close()
            fds = open("digitalSign.txt", "w")
            fds.write(s)
            fds.close()
            zipObj = ZipFile(attc, 'w')
            zipObj.write("document.txt")
            zipObj.write("digitalSign.txt")
            zipObj.close()
            out = m + "\n" + "<ds>" + str(s) + "</ds>"
    else:
        ft = open(textfile.filename, "r")
        m = ft.read()
        ft.close()
        md = sha256(m)
        pub = open(pub_file.filename, "rt")
        strpubk = pub.read()
        temp = [int(x) for x in strpubk.split(',')]
        e, n = temp[0], temp[1]
        pub.close()
        s = hex(pow(int(md, 16), e, n))[2:]
        if (req["outStyle"] == "intext"):
            attc = "signed_{}.txt".format(textfile.filename)
            out = m + "\n" + "<ds>" + str(s) + "</ds>"
            fs = open(attc, "w")
            fs.write(out)
            fs.close()
        else:
            attc = "signed_{}.zip".format(textfile.filename)
            doc = "document_{}.txt".format(textfile.filename)
            ds = "digitalSign_{}.txt".format(textfile.filename)
            fdoc = open(doc, "w")
            fdoc.write(m)
            fdoc.close()
            fds = open(ds, "w")
            fds.write(s)
            fds.close()
            zipObj = ZipFile(attc, 'w')
            zipObj.write(doc)
            zipObj.write(ds)
            zipObj.close()
            out = m + "\n" + "<ds>" + str(s) + "</ds>"
    return render_template('index.html', output=out + "\n \nText Digitally Signed! Click Download...")


@app.route("/verify", methods=["POST"])
def verif():
    global attc
    out = ""
    req = request.form
    f = request.files
    print(f)
    textfile = f["file"]
    dsfile = f["dsfile"]
    pri_file = f["prifile"]
    if textfile.filename != '':
        textfile.save(textfile.filename)
    if pri_file.filename != '':
        pri_file.save(pri_file.filename)
    if dsfile.filename != '':
        dsfile.save(dsfile.filename)
    if dsfile.filename != "":
        ft = open(textfile.filename, "rt")
        m = ft.read()
        ft.close()
        md = sha256(m)
        ft = open(dsfile.filename, "rt")
        s = ft.read()
        ft.close()
        pri = open(pri_file.filename, "rt")
        strprik = pri.read()
        temp = [int(x) for x in strprik.split(',')]
        d, n = temp[0], temp[1]
        pri.close()
        s_v = hex(pow(int(s, 16), d, n))[2:]
        v = hex(int(md, 16) % n)[2:]
        out = "Decrypt: {} \nVerifier: {} \n Tempered? {}".format(
            s_v, v, s_v != v)
    else:
        ft = open(textfile.filename, "rt")
        m = ft.read()
        ft.close()
        temp_m = re.findall(r'<[^>]*>.*?</[^>]*>(?:<[^>]*/>)?|[^<>]+', m)
        for t in temp_m:
            if t.find("<ds>") != -1:
                s = t
        temp_m.remove(s)
        s = s.replace("<ds>", "").replace("</ds>", "")
        print(s)
        if len(temp_m) != 1:
            m = "\n".join(temp_m)
        else:
            m = temp_m[0].strip()
        md = sha256(m)
        print(m)
        pri = open(pri_file.filename, "rt")
        strprik = pri.read()
        temp = [int(x) for x in strprik.split(',')]
        d, n = temp[0], temp[1]
        pri.close()
        s_v = hex(pow(int(s, 16), d, n))[2:]
        v = hex(int(md, 16) % n)[2:]
        out = "Decrypt: {} \n   Verifier: {} \n   Tempered? {}".format(
            s_v, v, s_v != v)
    attc = "verify_{}.txt".format(textfile.filename)
    fout = open(attc, "w")
    fout.write(out)
    fout.close()
    return render_template('index.html', output=out + "\n \nText Digitally Signed! Click Download...")


@app.route('/download')
def downloadFile():
    global attc
    print(attc)
    path = attc
    print(attc)
    return send_file(path, as_attachment=True)
