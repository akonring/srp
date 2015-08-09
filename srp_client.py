import hashlib
import random
import socket
import argh

# This is the client implementation of the SRV protocol.
# The client can issue a register request to the server:
#
# python srp_client.py register 'username' 'password'
#
# and he can authenticate himself afterwards using
# the SRP authentication protocol by issuing:
#
# python srp_client.py authenticate 'username' 'password'
#
# If the authentication process succeeds the protocol
# will yield a common session key
#
# The notation from http://srp.stanford.edu/design.html is used


# Reference: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
def H(*a):  # a one-way hash function
    a = ':'.join([str(a) for a in a])
    return int(hashlib.sha256(a.encode('ascii')).hexdigest(), 16)

# Reference: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
def cryptrand(n=1024):
    return random.SystemRandom().getrandbits(n) % N

# We assume that Client and Server have agreed on
# a generator, public modulus, hash function, multiplier parameter 
N = '''00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
       4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
       c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
       97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
       c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
       c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
       16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
       9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:
       d0:d4:ca:3c:50:0b:88:5f:e3'''
N = int(''.join(N.split()).replace(':', ''), 16) # public modulus

g = 2        # generator
k = H(N, g)  # multiplier parameter


# This is the TCP connection part

# Register sends a request to the Server containing v, s
def register(username, password):
    I = username         # Username
    p = password         # Password
    s = cryptrand(64)    # Salt 
    x = H(s, I, p)       # Private key
    v = pow(g, x, N)     # Password verifier

    # Register by sending (I, s, v) to the server
    sock.send("register" + " " + I + " " + str(s) + " " + str(v)) 
    print sock.recv(1024)

def authenticate(username, password):
    I = username         # Username
    p = password         # Password
    a = cryptrand()      # Secret ephemeral value
    A = pow(g, a, N)     # Public ephemeral value

    # Authenticate by sending (I, A) to the server
    sock.send("authenticate" + " " + username + " " + str(A))

    # Check Response
    s = sock.recv(1024)
    if s == "Error: Could not find username in database":
        print s
    else:
        # Generate session key
        s = long(s)
        B = long(sock.recv(1024))
        
        u = H(A, B)      # Random scrambling parameter
        x = H(s, I, p)
        S_c = pow(B - k * pow(g, x, N), a + u * x, N)
        K_c = H(S_c)

        # Verification process
        M_c = H(H(N) ^ H(g), H(I), s, A, B, K_c)
        sock.send(str(M_c))

        M_s_server = long(sock.recv(1024))
        M_s_client = H(A, M_c, K_c)

        # Check equality of keys
        if M_s_server == M_s_client:
            print "Authentication done and Sessionkey established:"
            print K_c
        else:
            print "Something went wrong in the authentication process:"

sock = socket.socket()

host = 'localhost'
port = 8080

# Connect to server
sock.connect((host, port))
print "Successfully connected to the SRV server"

# Generates arguments as specified in the top of the document
parser = argh.ArghParser()
parser.add_commands([register, authenticate])

if __name__ == '__main__':
    parser.dispatch()
    
sock.close()
