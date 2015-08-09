# Secure Remote Password Protocol

  This is a Python proof-of-concept implementation of the Secure Remote Password protocol.
  The notation used is similar to the one from the [original protocol design](http://srp.stanford.edu/design.html).
  Some code snippets are borrowed from [Wikipedia](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol).

  Bear in mind that this is only a poc implementation meaning that the server does not store the user data on any persistent storage i.e. a registered user will only be authenticated if the two requests occur in the same process life cycle.

## Server Usage
Open a terminal and launch the server

     python srp_server.py

## Client Usage
Clients can issue requests of type *register* or *authenticate*

### Client Register
To register on a running server issue the following command

     python srp_client.py register 'username' 'password'

### Client Authentication
To authenticate to the server     

     python srp_client.py authenticate 'username' 'password'


  
  
