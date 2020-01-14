from flask import Flask, render_template, redirect, url_for, request, session
from pymongo import MongoClient
from flask_uploads import UploadSet, IMAGES, configure_uploads
from bson import ObjectId
import datetime	
import hashlib
import time

app = Flask(__name__)
photos = UploadSet('photos', IMAGES)
app.config['UPLOADED_PHOTOS_DEST'] = 'static'
configure_uploads(app, photos)
app.config['SECRET_KEY'] = 'NEKI RANDOM STRING'
client = MongoClient("mongodb+srv://admin:admin@cluster0-pbeof.mongodb.net/test?retryWrites=true&w=majority")
db = client.get_database("db_kupovina")
users = db["users"]
proizvodi = db["proizvodi"]

@app.route('/')
@app.route('/index')
def index():
	p = list(proizvodi.find())
	uloga = ""
	korisnik = {}
	korisnik['type'] = "admin"
	if '_id' in session:
		korisnik = users.find_one({"_id": ObjectId(session["_id"])})
		return render_template('index.html',proizvodi = p,korisnik = korisnik,korisnici = users.find(), uloga=korisnik['type'])
	return render_template('index.html',proizvodi=p,korisnik = korisnik,korisnici = users.find())

@app.route('/registracija',methods = ["POST","GET"])
def registracija():
	if request.method == 'GET':
		return render_template('registracija.html')
		
	hash_object = hashlib.sha256(request.form['password'].encode())
	password_hashed = hash_object.hexdigest()

	if users.find_one({"username": request.form['username']}) is not None:
		return 'Korisničko ime već postoji!'
	username = request.form["username"]
	email = request.form["email"]
	password1 = request.form["password"]
	password2 = request.form["psw-repeat"]
	if password1 != password2:
		return "Lozinke se ne podudaraju!"
	pol = request.form["pol"]
	godina_rodjenja = request.form["godinaRodjenja"]
	tip_korisnika = request.form["usertype"]
	if 'slika' in request.files:
			photos.save(request.files['slika'], 'img', request.form['username'] + '.png')
	naziv_slike = request.form["username"] + ".png"
	
	
	unos = {
		"username":username,
		"email":email,
		"pol":pol,
		"godinRodjenja":godina_rodjenja,
		"password":password_hashed,
		"psw-repeat":password_hashed,
		'slika': "/static/img/" + naziv_slike,
		'created': time.strftime("%d-%m-%Y.%H:%M:%S"),
		"type": tip_korisnika,
		
	}
	users.insert_one(unos)
	return redirect(url_for('login'))

@app.route('/logout')
def logout():
	if "_id" in session:
		session.pop('_id',None)
		session.pop('type', None)
		return redirect(url_for('login'))
	return redirect(url_for('login'))

@app.route('/login', methods = ['GET', 'POST'])
def login():
	if '_id' in session:
		return "Vec ste ulogovani"+session['type']+" <br><a href='/'>idi na pocetnu</a>"
	if request.method == 'GET':
		return render_template('login.html')
	else:
		hash_object = hashlib.sha256(request.form['password'].encode())
		password_hashed = hash_object.hexdigest()
		user = users.find_one({'username':request.form['username'], 'password':password_hashed})
		if user is None:
			return redirect(url_for('login'))
		session['_id'] = str(user['_id'])
		session['type'] = user['type']
		return 'Uspesno ste ulogovani: ' + user['type']

@app.route('/dodaj_proizvod',methods = ["POST","GET"])
def dodaj_proizvod():
	if not "_id" in session or session["type"] != "seler":
		return redirect(url_for('login'))
	
	if request.method == "GET":
		return render_template("dodaj_proizvod.html")
	naziv = request.form["naziv"]
	if 'slika' in request.files:
			photos.save(request.files['slika'], 'img', request.form['naziv'] + '.png')
	cena = request.form['cena']
	kolicina = request.form['kolicina']
	naziv_slike = request.form["naziv"] + ".png"
	p = {
		'cena':cena,
		"naziv":naziv,
		"prodavac": str(session['_id']),
		'slika': "/static/img/" + naziv_slike,
		"kolicina": kolicina
	}
	proizvodi.insert_one(p)
	return redirect(url_for('index'))

@app.route('/delete_proizvod/<id>' , methods=['POST'])
def delete_proizvod(id):
	proizvod= proizvodi.find_one({"_id": ObjectId(session["_id"])})
	proizvodi.delete_one(proizvod)

	return "Proizvod "+proizvod['naziv']+" je uspesno obrisan!"

@app.route('/update_user/<id>', methods=['POST', "GET"])
def update_user(id):
	if request.method == "GET":
		return render_template('update_user.html',id=id )
	
	korisnik = users.find_one({'_id':ObjectId(id)})
	hash_object = hashlib.sha256(request.form['password'].encode())
	password_hashed = hash_object.hexdigest()

	email = request.form["email"]
	password1 = request.form["password"]
	password2 = request.form["psw-repeat"]
	if password1 != password2:
		return "Lozinke se ne podudaraju!"
	pol = request.form["pol"]
	godina_rodjenja = request.form["godinaRodjenja"]
	tip_korisnika = request.form["usertype"]
	if 'slika' in request.files:
		photos.save(request.files['slika'], 'slika', korisnik['username'] + '.png')
	slikaNaziv = korisnik['username'] + ".png"
	
	users.update_one({'_id':ObjectId(id)},{"$set":{"email":email,"password":password_hashed,"slika":"/static/img/" + slikaNaziv,"pol":pol,"godinaRodjenja":godina_rodjenja,"type":usertype}})
	return redirect(url_for('index'))
	
@app.route('/delete_korisnik/<id>')
def delete_korisnik(id):
	korisnik = users.find_one({'_id':ObjectId(id)})
	users.delete_one({'_id':ObjectId(id)})
	return "Korisnik "+korisnik['username']+" je uspesno obrisan!"

@app.route("/update_proizvod/<id>", methods=['POST', 'GET'])
def update_proizvod(id):
	if request.method == "GET":
		return render_template('update_proizvod.html',id=id )
		naziv = request.form["naziv"]
		if 'slika' in request.files:
				photos.save(request.files['slika'], 'img', request.form['naziv'] + '.png')
		cena = request.form['cena']
		kolicina = request.form['kolicina']
		slikaNaziv = request.form["naziv"] + ".png"
		
		proizvodi.update_one({'_id':ObjectId(id)},{"$set":{"naziv":naziv,"cena":cena,"slika":"/static/img/" + slikaNaziv,"kolicina":kolicina}})
		return redirect(url_for('index'))

if __name__ == '__main__':
	app.run(debug=True)