import socket
import threading
import pickle
import os
import sys
from cryptography.fernet import Fernet
import base64

groups = {}
fileTransferCondition = threading.Condition()

# Generate a key for encryption (in production, this should be securely shared)
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    """Encrypt data before sending"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif isinstance(data, int):
        data = str(data).encode('utf-8')
    return cipher_suite.encrypt(data)

def decrypt_data(encrypted_data):
    """Decrypt received data"""
    return cipher_suite.decrypt(encrypted_data)

def send_encrypted(client, data):
    """Send encrypted data to client"""
    if isinstance(data, str):
        encrypted_data = encrypt_data(data)
    else:
        encrypted_data = encrypt_data(data)
    
    # Send the length of encrypted data first, then the encrypted data
    data_length = len(encrypted_data)
    client.send(data_length.to_bytes(4, 'big'))
    client.send(encrypted_data)

def recv_encrypted(client):
    """Receive and decrypt data from client"""
    # First receive the length of encrypted data
    data_length = int.from_bytes(client.recv(4), 'big')
    
    # Then receive the encrypted data
    encrypted_data = b''
    while len(encrypted_data) < data_length:
        chunk = client.recv(min(data_length - len(encrypted_data), 4096))
        encrypted_data += chunk
    
    # Decrypt and return
    decrypted_data = decrypt_data(encrypted_data)
    return decrypted_data

class Group:
	def __init__(self,admin,client):
		self.admin = admin
		self.clients = {}
		self.offlineMessages = {}
		self.allMembers = set()
		self.onlineMembers = set()
		self.joinRequests = set()
		self.waitClients = {}

		self.clients[admin] = client
		self.allMembers.add(admin)
		self.onlineMembers.add(admin)

	def disconnect(self,username):
		self.onlineMembers.remove(username)
		del self.clients[username]
	
	def connect(self,username,client):
		self.onlineMembers.add(username)
		self.clients[username] = client

	def sendMessage(self,message,username):
		for member in self.onlineMembers:
			if member != username:
				encrypted_message = username + ": " + message
				send_encrypted(self.clients[member], encrypted_message)

def pyChat(client, username, groupname):
	while True:
		try:
			encrypted_msg = recv_encrypted(client)
			msg = encrypted_msg.decode("utf-8")
		except Exception as e:
			print(f"Error receiving message from {username}: {e}")
			break
			
		if msg == "/viewRequests":
			send_encrypted(client, "/viewRequests")
			try:
				recv_encrypted(client)  # Wait for acknowledgment
			except:
				continue
			if username == groups[groupname].admin:
				send_encrypted(client, "/sendingData")
				try:
					recv_encrypted(client)  # Wait for ready signal
					encrypted_requests = encrypt_data(pickle.dumps(groups[groupname].joinRequests))
					client.send(len(encrypted_requests).to_bytes(4, 'big'))
					client.send(encrypted_requests)
				except:
					continue
			else:
				send_encrypted(client, "You're not an admin.")
		elif msg == "/approveRequest":
			send_encrypted(client, "/approveRequest")
			try:
				recv_encrypted(client)  # Wait for acknowledgment
			except:
				continue
			if username == groups[groupname].admin:
				send_encrypted(client, "/proceed")
				try:
					usernameToApprove_encrypted = recv_encrypted(client)
					usernameToApprove = usernameToApprove_encrypted.decode("utf-8")
				except:
					continue
				if usernameToApprove in groups[groupname].joinRequests:
					groups[groupname].joinRequests.remove(usernameToApprove)
					groups[groupname].allMembers.add(usernameToApprove)
					if usernameToApprove in groups[groupname].waitClients:
						send_encrypted(groups[groupname].waitClients[usernameToApprove], "/accepted")
						groups[groupname].connect(usernameToApprove,groups[groupname].waitClients[usernameToApprove])
						del groups[groupname].waitClients[usernameToApprove]
					print("Member Approved:",usernameToApprove,"| Group:",groupname)
					send_encrypted(client, "User has been added to the group.")
				else:
					send_encrypted(client, "The user has not requested to join.")
			else:
				send_encrypted(client, "You're not an admin.")
		elif msg == "/disconnect":
			send_encrypted(client, "/disconnect")
			try:
				recv_encrypted(client)  # Wait for acknowledgment
			except:
				pass
			groups[groupname].disconnect(username)
			print("User Disconnected:",username,"| Group:",groupname)
			break
		elif msg == "/messageSend":
			send_encrypted(client, "/messageSend")
			try:
				message_encrypted = recv_encrypted(client)
				message = message_encrypted.decode("utf-8")
				groups[groupname].sendMessage(message,username)
			except:
				continue
		elif msg == "/waitDisconnect":
			send_encrypted(client, "/waitDisconnect")
			del groups[groupname].waitClients[username]
			print("Waiting Client:",username,"Disconnected")
			break
		elif msg == "/allMembers":
			send_encrypted(client, "/allMembers")
			try:
				recv_encrypted(client)  # Wait for acknowledgment
				encrypted_members = encrypt_data(pickle.dumps(groups[groupname].allMembers))
				client.send(len(encrypted_members).to_bytes(4, 'big'))
				client.send(encrypted_members)
			except:
				continue
		elif msg == "/onlineMembers":
			send_encrypted(client, "/onlineMembers")
			try:
				recv_encrypted(client)  # Wait for acknowledgment
				encrypted_members = encrypt_data(pickle.dumps(groups[groupname].onlineMembers))
				client.send(len(encrypted_members).to_bytes(4, 'big'))
				client.send(encrypted_members)
			except:
				continue
		elif msg == "/changeAdmin":
			send_encrypted(client, "/changeAdmin")
			try:
				recv_encrypted(client)  # Wait for acknowledgment
			except:
				continue
			if username == groups[groupname].admin:
				send_encrypted(client, "/proceed")
				try:
					newAdminUsername_encrypted = recv_encrypted(client)
					newAdminUsername = newAdminUsername_encrypted.decode("utf-8")
				except:
					continue
				if newAdminUsername in groups[groupname].allMembers:
					groups[groupname].admin = newAdminUsername
					print("New Admin:",newAdminUsername,"| Group:",groupname)
					send_encrypted(client, "Your adminship is now transferred to the specified user.")
				else:
					send_encrypted(client, "The user is not a member of this group.")
			else:
				send_encrypted(client, "You're not an admin.")
		elif msg == "/whoAdmin":
			send_encrypted(client, "/whoAdmin")
			try:
				groupname_encrypted = recv_encrypted(client)
				groupname = groupname_encrypted.decode("utf-8")
				send_encrypted(client, "Admin: "+groups[groupname].admin)
			except:
				continue
		elif msg == "/kickMember":
			send_encrypted(client, "/kickMember")
			try:
				recv_encrypted(client)  # Wait for acknowledgment
			except:
				continue
			if username == groups[groupname].admin:
				send_encrypted(client, "/proceed")
				try:
					usernameToKick_encrypted = recv_encrypted(client)
					usernameToKick = usernameToKick_encrypted.decode("utf-8")
				except:
					continue
				if usernameToKick in groups[groupname].allMembers:
					groups[groupname].allMembers.remove(usernameToKick)
					if usernameToKick in groups[groupname].onlineMembers:
						send_encrypted(groups[groupname].clients[usernameToKick], "/kicked")
						groups[groupname].onlineMembers.remove(usernameToKick)
						del groups[groupname].clients[usernameToKick]
					print("User Removed:",usernameToKick,"| Group:",groupname)
					send_encrypted(client, "The specified user is removed from the group.")
				else:
					send_encrypted(client, "The user is not a member of this group.")
			else:
				send_encrypted(client, "You're not an admin.")
		elif msg == "/fileTransfer":
			send_encrypted(client, "/fileTransfer")
			try:
				filename_encrypted = recv_encrypted(client)
				filename = filename_encrypted.decode("utf-8")
			except:
				continue
			if filename == "~error~":
				continue
			send_encrypted(client, "/sendFile")
			
			# Receive encrypted file data
			try:
				file_length_encrypted = recv_encrypted(client)
				remaining = int(file_length_encrypted.decode("utf-8"))
			except:
				continue
				
			# Receive encrypted file content
			encrypted_file_data = b''
			while len(encrypted_file_data) < remaining:
				chunk = client.recv(min(remaining - len(encrypted_file_data), 4096))
				encrypted_file_data += chunk
			
			# Decrypt file content
			try:
				file_data = decrypt_data(encrypted_file_data)
				with open(filename, "wb") as f:
					f.write(file_data)
			except Exception as e:
				print(f"Error decrypting file {filename}: {e}")
				continue
				
			print("File received:",filename,"| User:",username,"| Group:",groupname)
			
			# Send encrypted file to all other online members
			for member in groups[groupname].onlineMembers:
				if member != username:
					memberClient = groups[groupname].clients[member]
					send_encrypted(memberClient, "/receiveFile")
					with fileTransferCondition:
						fileTransferCondition.wait()
					send_encrypted(memberClient, filename)
					with fileTransferCondition:
						fileTransferCondition.wait()
					
					# Send encrypted file data
					with open(filename,'rb') as f:
						data = f.read()
						encrypted_data = encrypt_data(data)
						send_encrypted(memberClient, str(len(encrypted_data)))
						memberClient.send(encrypted_data)
						
			send_encrypted(client, filename+" successfully sent to all online group members.")
			print("File sent",filename,"| Group: ",groupname)
			os.remove(filename)
		elif msg == "/sendFilename" or msg == "/sendFile":
			with fileTransferCondition:
				fileTransferCondition.notify()
		else:
			print("UNIDENTIFIED COMMAND:",msg)
def handshake(client):
	# First, send the encryption key to the client
	client.send(ENCRYPTION_KEY)
	
	try:
		username_encrypted = recv_encrypted(client)
		username = username_encrypted.decode("utf-8")
		send_encrypted(client, "/sendGroupname")
		groupname_encrypted = recv_encrypted(client)
		groupname = groupname_encrypted.decode("utf-8")
	except Exception as e:
		print(f"Error during handshake: {e}")
		client.close()
		return
		
	if groupname in groups:
		if username in groups[groupname].allMembers:
			groups[groupname].connect(username,client)
			send_encrypted(client, "/ready")
			print("User Connected:",username,"| Group:",groupname)
		else:
			groups[groupname].joinRequests.add(username)
			groups[groupname].waitClients[username] = client
			groups[groupname].sendMessage(username+" has requested to join the group.","PyChat")
			send_encrypted(client, "/wait")
			print("Join Request:",username,"| Group:",groupname)
		threading.Thread(target=pyChat, args=(client, username, groupname,)).start()
	else:
		groups[groupname] = Group(username,client)
		threading.Thread(target=pyChat, args=(client, username, groupname,)).start()
		send_encrypted(client, "/adminReady")
		print("New Group:",groupname,"| Admin:",username)

def main():
	if len(sys.argv) < 3:
		print("USAGE: python server.py <IP> <Port>")
		print("EXAMPLE: python server.py localhost 8000")
		return
	listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	listenSocket.bind((sys.argv[1], int(sys.argv[2])))
	listenSocket.listen(10)
	print("PyChat Server running")
	while True:
		client,_ = listenSocket.accept()
		threading.Thread(target=handshake, args=(client,)).start()

if __name__ == "__main__":
	main()
