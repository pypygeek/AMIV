#-*- coding: utf-8 -*-
import axmlprinter
from xml.etree.ElementTree import parse 
from xml.dom import minidom
import hashlib, os, sys, zipfile, struct, mmap, re,shutil 
import json, urllib, urllib2, argparse

#Remove TempFolder
def Remove_Temp() :
	try:
		shutil.rmtree('AMIV_Temp')
	except OSError as e:
		pass

#Create AMIVReport.txt 
Report = open('AMIVReport.txt', 'w')

filename = sys.argv[1]

#Read File 
try:
	f = open(filename, 'rb')
	data = f.read()
except IndexError:
	Report.write('ERROR : AMIV.exe example.apk')
	sys.exit()
except IOError:
	Report.write('ERROR : AMIV.exe example.apk')
	sys.exit()
except NameError:
	Report.write('ERROR : Choose File')

def apkCheck():
	if '\xFE\xCA\x00\x00' in data:
		#Unzip
		try :
			fzip = zipfile.ZipFile(f, 'r')
			fzip.extractall(path='./AMIV_Temp')
			fzip.close()
			#check valid apk file
			street = './AMIV_Temp'
			for root, dirs, files in os.walk(street):
				for file in files:
					if file == 'AndroidManifest.xml':
						return True
					elif 'resources.arsc' in file:
						return True
					elif 'Classes.dex' in file:
						return True
					else: 
						Report.write('ERROR : Corrupted APK File')
						sys.exit()
		except RuntimeError:
			Report.write('ERROR : PassWorld File or Unknow Error')
			Remove_Temp()
			sys.exit()
		except zipfile.BadZipfile:
			Report.write('ERROR : Faile Unzip')
			sys.exit()
		except NameError:
			Report.write('ERROR : Choose APK File')
	else: 
		Report.write('ERROR : NOT a APK')
apkCheck()

#Read Classes.dex	
try:
	fp = open('./AMIV_Temp/classes.dex', 'rb')
	mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
	fp.close()
except IOError:
	Report.write('\nNot Found Classes.dex\n')
	Remove_Temp()
	sys.exit()
	
def Print_Logo():
	Report.write('=' * 75)
	Report.write('\n\nAndroid Malware Info Visibility [Ver 2.7] Report')
	Report.write('\nBlog:http://geeklab.tistory.com/')
	Report.write('\nE-mail:geeklab@naver.com')

Print_Logo()

def File_Info():	
	Report.write('\n\n=============================File Information==============================')
	Report.write('\n\nFile Name : ' + os.path.basename(filename).encode('utf-8'))
	Report.write('\nMD5 : ' + hashlib.md5(data).hexdigest())
	Report.write('\nSHA-1 : ' + hashlib.sha1(data).hexdigest())
	Report.write('\nSHA-256 : ' + hashlib.sha256(data).hexdigest())
	Report.write('\nFile Size : ' + str(os.path.getsize(filename)) + ' Byte\n')

File_Info()

def App_Info():
	#AndroidManifest.xml Parsing 
	ap = axmlprinter.AXMLPrinter(open('./AMIV_Temp/AndroidManifest.xml', 'rb').read())
	buff = minidom.parseString(ap.getBuff()).toxml()
	
	#Create AndroidManifest.xml Parsing Data Temp File
	fx = open('./AMIV_Temp/AndroidManifestTemp','w')
	fx.write(buff.encode('utf-8'))
	fx.close()
	tree = parse('./AMIV_Temp/AndroidManifestTemp')
	note = tree.getroot()
	for pack in note.iter('manifest'):
		Report.write('\n==============================APP Information==============================\n')
		m = pack.attrib.values()
		Report.write('\nPackage: ' + str(pack.attrib.values() [0]))
	for per in note.iter('uses-permission'):
		Report.write('\nPermission: ' + str(per.attrib.values() [0]))
	for rec in note.iter('receiver'):
		Report.write('\nReciver: ' + str(rec.attrib.values() [0]))
	for ser in note.iter('service'):
		Report.write('\nService: ' + str(ser.attrib.values() [0]))

	
try:
	App_Info()
except IOError:
	Report.write('Not found AndroidManifest.xml')

#class.dex struct analysis	
def header(mm):
	file_size       = struct.unpack('<L', mm[0x20:0x24])[0]
	string_ids_size = struct.unpack('<L', mm[0x38:0x3C])[0]
	string_ids_off  = struct.unpack('<L', mm[0x3C:0x40])[0]
    

	hdr = {}

	if len(mm) != file_size :
		return hdr

		
	hdr['string_ids_size'] = string_ids_size
	hdr['string_ids_off' ] = string_ids_off
    

	return hdr

try:
	hdr = header(mm)
except NameError:
	pass
	
def string_id_list(mm, hdr):
    string_id = [] #Save ALL Strings Data

    string_ids_size = hdr['string_ids_size']
    string_ids_off  = hdr['string_ids_off' ]

    for i in range(string_ids_size) :
        off = struct.unpack('<L', mm[string_ids_off+(i*4):string_ids_off+(i*4)+4])[0]
        c_size = ord(mm[off])
        c_char = mm[off+1:off+1+c_size]

        string_id.append(c_char)

    return string_id

try:
	string_ids = string_id_list(mm, hdr)
except NameError:
	pass

Report.write('\n\n=============================Interested Strings=============================\n')

def Patten_extract():
	for i in range(len(string_ids)) :
		UrlRegular = re.search('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string_ids[i])
		IpRegular = re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', string_ids[i])
		EmailRegular = re.search('\w+@\w+\.\w+', string_ids[i])
	
		try:
			Report.write('\nURL: ' + UrlRegular.group())
		except AttributeError:
			pass
		try:
			Report.write('\nIP: ' + IpRegular.group())
		except AttributeError:
			pass
		try:
			Report.write('\nE-mail: ' + EmailRegular.group())
		except AttributeError:
			pass

try:
	Patten_extract()
	mm.close()
except NameError:
	pass
	
Remove_Temp()
Report.close()
sys.exit()
