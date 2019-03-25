import fcp
from Crypto.Hash import SHA256
import os
from os.path import isfile
import magic
import pickle
import tempfile

class SampleManager:

	def __init__(self, private, public):
		self.samples = dict()
		self.lastInsert = None
		self.recentinserts = []
		self.stats = dict()
		self.insertreqs = []
		self.public=public
		self.private=private

	#Add a directory full of samples to our list
	def addsampledir(self, path):
		filenames = [f for f in os.listdir(path) if isfile(path + f)]
		for f in filenames:
			self.addsample(Sample(path+f))

	# Add one sample 
	def addsample(self, sample):
		self.samples[sample.sha256sum] = sample
	
	# Remove one sample
	def removesample(self, sha256sum):
		self.samples.pop(sha256sum)
	
	def publishupdate(self, node):
		tempdir = tempfile.mkdtemp()
		scrubbedpaths = dict()
		for v in self.samples.values():
			v.path = ""
			scrubbedpaths[v.sha256sum] = v
		with open(os.path.join(tempdir,"samplelist"), "w") as f:
			pickle.dump(scrubbedpaths,f)
		with open(os.path.join(tempdir, "recentinserts"), "w") as f:
			pickle.dump(self.recentinserts,f)
		with open(os.path.join(tempdir, "stats"), "w") as f:
			pickle.dump(self.stats,f)
		with open(os.path.join(tempdir, "insertreqs"), "w") as f:
			pickle.dump(self.insertreqs,f)

		self.recentinserts = [] #clear out our list of recent inserts

		return node.putdir(uri=self.private, dir=tempdir, name="phageproto", filebyfile=True, allatonce=True, globalqueue=True, usk=True, priority=1)

	def publishsample(self, sample, node):
		self.samples[sample.sha256sum].chk = node.put(file=sample.path)
		sample.path=""
		self.recentinserts.append(sample)
		return self.samples[sample.sha256sum].chk
	
	#import a set of samples from a published list	 
	def importsamples(self, pubkey, node):
		data = node.get(uri=pubkey + "samplelist")
		s = pickle.loads(data[1])
		self.samples.update(s)
		return s

	def samplesstats(self):
		totalsize = 0
		numsamples = len(self.samples)
		for v in self.samples.values():
			totalsize += v.size
		self.stats['totalsize'] = totalsize
		self.stats['numsamples'] = numsamples	

class Sample:

	# Derive all of our needed information from a path
	def __init__(self, path):
		h = SHA256.new()
		f = open(path, 'rb')
		for l in f:
			h.update(l)
		self.path=path
		self.sha256sum=h.hexdigest()
		self.magictype=magic.from_file(path)
		self.size=os.lstat(path).st_size
		#self.detectratio=detectratio Add code for detection ratio later

