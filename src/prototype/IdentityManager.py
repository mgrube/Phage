import fcp 
import pickle

#Functions we want:
#	Add
#	Revoke
#	AssignKey
# How does this work? 

class IdentityManager:

	trustedkeys = []
	revokedkeys = []
	pub = None
	priv = None

	def __init__(self, pub, priv):
		self.pub = pub
		self.priv = priv
		

	def trustident(self, pubkey):
		self.trustedkeys.append(pubkey)

	def revokeident(self, pubkey):
		try:
			self.trustedkeys.remove(pubkey)
		except ValueError:
			pass
		self.revokedkeys.append(pubkey)

	def updatelists(self, node):
		node.put(uri=self.priv + "revokedkeys", data=pickle.dumps(self.revokedkeys))
		node.put(uri=self.priv + "trustedkeys", data=pickle.dumps(self.trustedkeys))

	def importkeys(self, pubkey, node):
		trusted = pickle.loads(node.get(uri=pubkey + "trustedkeys")[1])
		revoked = pickle.loads(node.get(uri=pubkey + "revokedkeys")[1])
		self.trustedkeys = list(set(self.trustedkeys+trusted))
		self.revokedkeys = list(set(self.revokedkeys+revoked))
		 
		
