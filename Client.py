import socket
import threading
import pickle
import sys
from cryptography.fernet import Fernet

state = {}
cipher_suite = None

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
    """Send encrypted data to server"""
    if isinstance(data, str):
        encrypted_data = encrypt_data(data)
    else:
        encrypted_data = encrypt_data(data)
    
    # Send the length of encrypted data first, then the encrypted data
    data_length = len(encrypted_data)
    client.send(data_length.to_bytes(4, 'big'))
    client.send(encrypted_data)

def recv_encrypted(client):
    """Receive and decrypt data from server"""
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

def serverListen(serverSocket):
	while True:
		try:
			msg_encrypted = recv_encrypted(serverSocket)
			msg = msg_encrypted.decode("utf-8")
		except Exception as e:
			print(f"Connection error: {e}")
			break
			
		if msg == "/viewRequests":
			send_encrypted(serverSocket, ".")
			try:
				response_encrypted = recv_encrypted(serverSocket)
				response = response_encrypted.decode("utf-8")
			except:
				continue
			if response == "/sendingData":
				send_encrypted(serverSocket, "/readyForData")
				try:
					# Receive encrypted pickled data
					data_length = int.from_bytes(serverSocket.recv(4), 'big')
					encrypted_data = b''
					while len(encrypted_data) < data_length:
						chunk = serverSocket.recv(min(data_length - len(encrypted_data), 4096))
						encrypted_data += chunk
					decrypted_data = decrypt_data(encrypted_data)
					data = pickle.loads(decrypted_data)
				except:
					continue
				if data == set():
					print("No pending requests.")
				else:
					print("Pending Requests:")
					for element in data:
						print(element)
			else:
				print(response)
		elif msg == "/approveRequest":
			send_encrypted(serverSocket, ".")
			try:
				response_encrypted = recv_encrypted(serverSocket)
				response = response_encrypted.decode("utf-8")
			except:
				continue
			if response == "/proceed":
				state["inputMessage"] = False
				print("Please enter the username to approve: ")
				with state["inputCondition"]:
					state["inputCondition"].wait()
				state["inputMessage"] = True
				send_encrypted(serverSocket, state["userInput"])
				try:
					result_encrypted = recv_encrypted(serverSocket)
					result = result_encrypted.decode("utf-8")
					print(result)
				except:
					continue
			else:
				print(response)
		elif msg == "/disconnect":
			send_encrypted(serverSocket, ".")
			state["alive"] = False
			break
		elif msg == "/messageSend":
			send_encrypted(serverSocket, state["userInput"])
			state["sendMessageLock"].release()
		elif msg == "/allMembers":
			send_encrypted(serverSocket, ".")
			try:
				# Receive encrypted pickled data
				data_length = int.from_bytes(serverSocket.recv(4), 'big')
				encrypted_data = b''
				while len(encrypted_data) < data_length:
					chunk = serverSocket.recv(min(data_length - len(encrypted_data), 4096))
					encrypted_data += chunk
				decrypted_data = decrypt_data(encrypted_data)
				data = pickle.loads(decrypted_data)
				print("All Group Members:")
				for element in data:
					print(element)
			except:
				continue
		elif msg == "/onlineMembers":
			send_encrypted(serverSocket, ".")
			try:
				# Receive encrypted pickled data
				data_length = int.from_bytes(serverSocket.recv(4), 'big')
				encrypted_data = b''
				while len(encrypted_data) < data_length:
					chunk = serverSocket.recv(min(data_length - len(encrypted_data), 4096))
					encrypted_data += chunk
				decrypted_data = decrypt_data(encrypted_data)
				data = pickle.loads(decrypted_data)
				print("Online Group Members:")
				for element in data:
					print(element)
			except:
				continue
		elif msg == "/changeAdmin":
			send_encrypted(serverSocket, ".")
			try:
				response_encrypted = recv_encrypted(serverSocket)
				response = response_encrypted.decode("utf-8")
			except:
				continue
			if response == "/proceed":
				state["inputMessage"] = False
				print("Please enter the username of the new admin: ")
				with state["inputCondition"]:
					state["inputCondition"].wait()
				state["inputMessage"] = True
				send_encrypted(serverSocket, state["userInput"])
				try:
					result_encrypted = recv_encrypted(serverSocket)
					result = result_encrypted.decode("utf-8")
					print(result)
				except:
					continue
			else:
				print(response)
		elif msg == "/whoAdmin":
			send_encrypted(serverSocket, state["groupname"])
			try:
				result_encrypted = recv_encrypted(serverSocket)
				result = result_encrypted.decode("utf-8")
				print(result)
			except:
				continue
		elif msg == "/kickMember":
			send_encrypted(serverSocket, ".")
			try:
				response_encrypted = recv_encrypted(serverSocket)
				response = response_encrypted.decode("utf-8")
			except:
				continue
			if response == "/proceed":
				state["inputMessage"] = False
				print("Please enter the username to kick: ")
				with state["inputCondition"]:
					state["inputCondition"].wait()
				state["inputMessage"] = True
				send_encrypted(serverSocket, state["userInput"])
				try:
					result_encrypted = recv_encrypted(serverSocket)
					result = result_encrypted.decode("utf-8")
					print(result)
				except:
					continue
			else:
				print(response)
		elif msg == "/kicked":
			state["alive"] = False
			state["inputMessage"] = False
			print("You have been kicked. Press any key to quit.")
			break
		elif msg == "/fileTransfer":
			state["inputMessage"] = False
			print("Please enter the filename: ")
			with state["inputCondition"]:
				state["inputCondition"].wait()
			state["inputMessage"] = True
			filename = state["userInput"]
			try:
				f = open(filename,'rb')
				f.close()
			except FileNotFoundError:
				print("The requested file does not exist.")
				send_encrypted(serverSocket, "~error~")
				continue
			send_encrypted(serverSocket, filename)
			try:
				recv_encrypted(serverSocket)  # Wait for ready signal
			except:
				continue
			print("Uploading file to server...")
			with open(filename,'rb') as f:
				data = f.read()
				encrypted_data = encrypt_data(data)
				send_encrypted(serverSocket, str(len(encrypted_data)))
				serverSocket.send(encrypted_data)
			try:
				result_encrypted = recv_encrypted(serverSocket)
				result = result_encrypted.decode("utf-8")
				print(result)
			except:
				continue
		elif msg == "/receiveFile":
			print("Receiving shared group file...")
			send_encrypted(serverSocket, "/sendFilename")
			try:
				filename_encrypted = recv_encrypted(serverSocket)
				filename = filename_encrypted.decode("utf-8")
				send_encrypted(serverSocket, "/sendFile")
				file_length_encrypted = recv_encrypted(serverSocket)
				remaining = int(file_length_encrypted.decode("utf-8"))
				
				# Receive encrypted file data
				encrypted_file_data = serverSocket.recv(remaining)
				
				# Decrypt and save file
				file_data = decrypt_data(encrypted_file_data)
				with open(filename, "wb") as f:
					f.write(file_data)
				print("Received file saved as",filename)
			except Exception as e:
				print(f"Error receiving file: {e}")
		else:
			print(msg)

def userInput(serverSocket):
	while state["alive"]:
		state["sendMessageLock"].acquire()
		state["userInput"] = input()
		state["sendMessageLock"].release()
		with state["inputCondition"]:
			state["inputCondition"].notify()
		if state["userInput"] == "/1":
			send_encrypted(serverSocket, "/viewRequests")
		elif state["userInput"] == "/2":
			send_encrypted(serverSocket, "/approveRequest")
		elif state["userInput"] == "/3":
			send_encrypted(serverSocket, "/disconnect")
			break
		elif state["userInput"] == "/4":
			send_encrypted(serverSocket, "/allMembers")
		elif state["userInput"] == "/5":
			send_encrypted(serverSocket, "/onlineMembers")
		elif state["userInput"] == "/6":
			send_encrypted(serverSocket, "/changeAdmin")
		elif state["userInput"] == "/7":
			send_encrypted(serverSocket, "/whoAdmin")
		elif state["userInput"] == "/8":
			send_encrypted(serverSocket, "/kickMember")
		elif state["userInput"] == "/9":
			send_encrypted(serverSocket, "/fileTransfer")
		elif state["inputMessage"]:
			state["sendMessageLock"].acquire()
			send_encrypted(serverSocket, "/messageSend")

def waitServerListen(serverSocket):
	while not state["alive"]:
		try:
			msg_encrypted = recv_encrypted(serverSocket)
			msg = msg_encrypted.decode("utf-8")
		except:
			break
		if msg == "/accepted":
			state["alive"] = True
			print("Your join request has been approved. Press any key to begin chatting.")
			break
		elif msg == "/waitDisconnect":
			state["joinDisconnect"] = True
			break

def waitUserInput(serverSocket):
	while not state["alive"]:
		state["userInput"] = input()
		if state["userInput"] == "/1" and not state["alive"]:
			send_encrypted(serverSocket, "/waitDisconnect")
			break

def main():
	global cipher_suite
	if len(sys.argv) < 3:
		print("USAGE: python client.py <IP> <Port>")
		print("EXAMPLE: python client.py localhost 8000")
		return
	serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	serverSocket.connect((sys.argv[1], int(sys.argv[2])))
	
	# Receive encryption key from server
	encryption_key = serverSocket.recv(44)  # Fernet key is 44 bytes
	cipher_suite = Fernet(encryption_key)
	
	state["inputCondition"] = threading.Condition()
	state["sendMessageLock"] = threading.Lock()
	state["username"] = input("Welcome to PyChat! Please enter your username: ")
	state["groupname"] = input("Please enter the name of the group: ")
	state["alive"] = False
	state["joinDisconnect"] = False
	state["inputMessage"] = True
	
	send_encrypted(serverSocket, state["username"])
	try:
		recv_encrypted(serverSocket)  # Wait for sendGroupname signal
		send_encrypted(serverSocket, state["groupname"])
		response_encrypted = recv_encrypted(serverSocket)
		response = response_encrypted.decode("utf-8")
	except Exception as e:
		print(f"Connection error: {e}")
		return
		
	if response == "/adminReady":
		print("You have created the group",state["groupname"],"and are now an admin.")
		state["alive"] = True
	elif response == "/ready":
		print("You have joined the group",state["groupname"])
		state["alive"] = True
	elif response == "/wait":
		print("Your request to join the group is pending admin approval.")
		print("Available Commands:\n/1 -> Disconnect\n")
	waitUserInputThread = threading.Thread(target=waitUserInput,args=(serverSocket,))
	waitServerListenThread = threading.Thread(target=waitServerListen,args=(serverSocket,))
	userInputThread = threading.Thread(target=userInput,args=(serverSocket,))
	serverListenThread = threading.Thread(target=serverListen,args=(serverSocket,))
	waitUserInputThread.start()
	waitServerListenThread.start()
	while True:
		if state["alive"] or state["joinDisconnect"]:
			break
	if state["alive"]:
		print("Available Commands:\n/1 -> View Join Requests (Admins)\n/2 -> Approve Join Requests (Admin)\n/3 -> Disconnect\n/4 -> View All Members\n/5 -> View Online Group Members\n/6 -> Transfer Adminship\n/7 -> Check Group Admin\n/8 -> Kick Member\n/9 -> File Transfer\nType anything else to send a message")
		waitUserInputThread.join()
		waitServerListenThread.join()
		userInputThread.start()
		serverListenThread.start()
	while True:
		if state["joinDisconnect"]:
			serverSocket.shutdown(socket.SHUT_RDWR)
			serverSocket.close()
			waitUserInputThread.join()
			waitServerListenThread.join()
			print("Disconnected from PyChat.")
			break
		elif not state["alive"]:
			serverSocket.shutdown(socket.SHUT_RDWR)
			serverSocket.close()
			userInputThread.join()
			serverListenThread.join()
			print("Disconnected from PyChat.")
			break

if __name__ == "__main__":
	main()
