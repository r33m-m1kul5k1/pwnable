
>We have isolated the authentication procedure to another box using RPC. 
>The credential information between RPC is encrypted with AES-CBC, so it will be secure enough from  sniffing.
>I believe no one can login as admin but me :p

RPC stands for Remote Procedural Call

`# guest / 8b465d23cb778d3636bf6c4c5e30d031675fd95cec7afea497d36146783fd3a1`
## understanding the challenge
We get a server that calls authentication function of the client using RPC. The AES block chunk is 128 bits  (16 bytes).

The client enters it's ID and a Password. Then we get the cipher.
If we log in as a guest we are told to log as a admin, and if we do we get the flag!
#### restrictions
The ID and the Password must include only these  `1234567890abcdefghijklmnopqrstuvwxyz-_` characters.
#### info
the key, IV and cookie are constants
`[id]-[pw]-[cookie]`
<sup> if the password includes `-` we can change the cookie </sup>
`pw = hash(id+cookie)`
```text
Input your ID
guest
Input your PW
8b465d23cb778d3636bf6c4c5e30d031675fd95cec7afea497d36146783fd3a1
sending encrypted data (f5396cbe5606ee8fc18bffd1cf6fdd04951eaa82fd805b41381863243b7461160fab3f5ed0067680af3357bdbed352d7cbf9456ead7ec54b52bda9fe6d7aa35db8bee8945fd376489f815cf3cf07d8302ed2b4a461ce84f1cc46ae0e39a63c8df361ba06eafdc5f9b36fe38c95db1572482b5a5db8fae8d394de084b1b7e92a8)
hi guest, login as admin
```

#### goal
find the cookie value :)
## vulnerability
* static IV & cookie (each encryption of the same data is the same)
* [bit flipping attack](https://alicegg.tech/2019/06/23/aes-cbc.html)
* [chosen plaintext attack](https://derekwill.com/2021/01/01/aes-cbc-mode-chosen-plaintext-attack/)
* padding oracle
is clearly the CBC mode

## abilities
* change the cookie value by adding `-` to the password
* run the encryption with the same IV and key
### ECB (Electronic Code Book) mode
![[Pasted image 20231215113224.png]]
data patterns might remain... 
* encrypting the same text block yields the same ciphertext block. 
* substrings with the same alignment yields the same ciphertext pattern (prefix & suffix)
### CBC mode
each iteration you XOR the plaintext with the previous encrypted ciphertext, then you encrypt it.
###### encryption
![[Pasted image 20231215114419.png]]
###### decryption
each iteration you XOR the plaintext with the previous encrypted ciphertext.
![[Pasted image 20231215114459.png]]

### flipping attack
![[Pasted image 20231215115320.png]]
If you flip a bit in the previous ciphertext / IV the plaintext will get flipped on the same bit.
`bits_to_flip (plaintext ^ new_text)`
`IV = IV ^ bits_to_flip` 
You need some control over the IV / ciphertext.
### Chosen Plaintext Attack

#### deducing one byte
Alice `cookie` first char is included in the block
```
if E(|x*15c|) == E(|x*15X|):
    Congraz!
```



### focus
* getting the cookie
* understanding how CBC can help me
* using the guest pw & using the - trick

The cookie is inside the encrypted message. If I could decrypt it I win.

CBC with static key and IV:
* CBC with static IV gives me a way to rerun guesses.
* CBC takes the cipher / IV and XOR it with the yet to be encrypted plaintext

Using the guest pw I can:
1. verify that I got the right cookie
2. it's a way to show me that the pw is sha256(id+cookie)

Using the `-` trick can:
1. change the cookie to whatever I want
2. test if my guest cookie is valid (cookie oracle)


### Implementation

```
xxxxxxxxxxxxxx-p
xxxxxxxxxxxxxxp-
```
now my problem is the `-` I can put my guess inside the field of the password. now my guess works.
```python
cookie = ''
# '|xxxxxxxxxxxxxx-p|assword'
padding_len = 14 
# put at the end of the choosen block one byte of the cookie
alice_cipher = sniff('x'*(padding_len), 'password')
log.info(f'Alice block: {alice_cipher[0:16*2]}')

char = 'p'
# put char at the end of the choosen block
eve_cipher = sniff('x'*(padding_len), char)
log.info(f'Eve block: {eve_cipher[0:16*2]}')
if alice_cipher[0:16*2] == eve_cipher[0:16*2]:
    cookie += char
    print(f'cookie: {cookie}') 
```

```
|-xxxxxxxxxxxxx-c|ookie
guest = ''
pw = 'xxxxxxxxxxxxx-X'
|-xxxxxxxxxxxxx-X|-cookie
```

final nasty code
```python
BLOCK_OFFSET = 16*3
padding_len = BLOCK_OFFSET + 12 - 28
# you_will_never_guess_this_sugar_honey_salt_cookie
cookie = 'you_will_never_guess_this_sug'

while padding_len > 0:
    # put at the end of the choosen block one byte of the cookie
    alice_cipher = sniff('', 'x'*(padding_len))
    log.info(f'Alice block: {alice_cipher[BLOCK_OFFSET*2:BLOCK_OFFSET*2 + 16*2]}')


    for char in '1234567890abcdefghijklmnopqrstuvwxyz-_':
        # put char at the end of the choosen block
        eve_cipher = sniff('', 'x'*(padding_len) + '-' + cookie + char)
        log.info(f'Eve block: {eve_cipher[BLOCK_OFFSET*2:BLOCK_OFFSET*2 + 16*2]}')
        if alice_cipher[BLOCK_OFFSET*2:BLOCK_OFFSET*2 + 16*2] == eve_cipher[BLOCK_OFFSET*2:BLOCK_OFFSET*2 + 16*2]:
            cookie += char
            print(f'cookie: {cookie}') 
            break
    
    padding_len -= 1
```


# writeups
## booky (corrupting ciphertext)
Solution to crypto1 by Booky
1. Does not require hyphens in input to client. Talks to server directly.
2. CBC oracle attack, corrupts ciphertext and checks whether the
   server faults due to missing hyphens in decrypted packet.
   If not, gleans information about possible values of plaintext.
3. The information produced by using this technique on a single request
   gives multiple possible values for the plaintext byte because a hyphen
   may be produced by the decryption of the corrupted ciphertext block,
   not only by the intended modification of the next block's byte to a hyphen.
4. Therefore, gleaned information is cross-referenced across multiple
   pre-recorded requests to reduce cookie option space.
```python
import binascii
import xmlrpclib
import hashlib
import socket
import contextlib

_PROXY = xmlrpclib.ServerProxy('http://127.0.0.1:9100/')
_HYPHEN = ord('-')
_USERNAME = 'admin'
_BLOCK_SIZE = 16
_COOKIE_LENGTH = 49
_ORIG_REQUESTS = map(binascii.unhexlify, [
    # username = password = 'aaaabbbbccccddd'
    'baca23440b0b441692a78fc3c1c4b66626269f37daeae925ea39f35fac8cc1d95a9646d6a76876c5a88fe00ff499f729'
    '6c779d061e872f28131cf39718529a253d06fdae1b8fb1cf68a64a444b2883eae97bceb2c7e0ac43ebb8e6caa947b64a',
    # username = password = 'ddddbbbbccccaaa'
    '322408aa3fe730f38c3ca93f64ada5c974367d7b8b6d2614901e2fdc87d97077c3d29b207b3abc925f23982a77ff48a9'
    '817f091db1b42caf0eb2988177c1322058a9e8762cd0c7fc19587aaa45d5189459c30932c3ef984b7976d31b31b932ee',
    # username = password = 'derpderpderpzzz'
    '22e0b418f5bc2f6a835dc1a34948ba9df0052c9567f5a1afe07b5b21887e42cf82597092614e2646678844554770c524'
    '4929c34403f3282493c6228d045d404a686c05de34d3f5ff4bc30bf15f96c452d4d87e54b853281d7e86f63db9d9da51',
    # username = password = '123412341234777'
    '87c5d973f54d41edf3c355702841adc67753fdaf5dc86665115af546c721201d2eaffc77077e971157869582a298e8ab'
    '6026f4cbf73dc2f2cd7a5a79a74237c81e33caf1509f86610ce8daafa41d6133086dc4f6641faef8bfcae9f57568ce6b',
    # username = password = 'qwerasdfzxcv123'
    '012648945af5b66d477e77aa356815a5f4b697231d3bf483588eaf2c03201ed85df674cc35f765ec47d5b9139985a006'
    '83db09ad9bc16d50397fb3c1604f5b53f54100e8d81136a112d8e273a62bc092f72d29d4439214b67fcf98f4ff758c86',
])


def modify(orig_request, cookie_offset, value):
    cookie_start_offset = 2*_BLOCK_SIZE
    modify_offset = cookie_start_offset + cookie_offset - _BLOCK_SIZE

    modified_request = bytearray(orig_request)
    old_value = modified_request[modify_offset]
    modified_request[modify_offset] = value

    # Hack - corrupt the second block's hyphen
    if cookie_offset >= _BLOCK_SIZE:
        modified_request[_BLOCK_SIZE] = 0

    return str(modified_request), old_value


def check_hyphens(req_bin):
    # Oracle - does the decrypted packet contain at least two hyphens or not?
    req = binascii.hexlify(req_bin)
    try:
        res = _PROXY.authenticate(req)
        assert res == 0
        return True

    except xmlrpclib.Fault as e:
        return False


def format_cookie_options(cookie_list):
    result = ''
    for candidate_list in cookie_list:
        assert len(candidate_list) != 0
        if len(candidate_list) == 1:
            result += candidate_list[0]
        else:
            result += '[{}]'.format('|'.join(candidate_list))
    return result


stolen_cookie = []
for offset in xrange(_COOKIE_LENGTH):
    print 'Determining cookie value at offset = {}'.format(offset)
    candidates = set(xrange(0x100))

    for orig_request in _ORIG_REQUESTS:
        cur_candidates = set()

        for corruption_byte in xrange(0x100):
            modified, original_byte = modify(orig_request, offset, corruption_byte)
            if corruption_byte == original_byte:
                continue

            if check_hyphens(modified):
                cur_candidates.add(corruption_byte ^ original_byte ^ _HYPHEN)

        candidates &= cur_candidates

    stolen_cookie.append([chr(b) for b in candidates])


formatted_cookie = format_cookie_options(stolen_cookie)
print 'Cookie: {}'.format(formatted_cookie)
if all(len(c) == 1 for c in stolen_cookie):
    print 'Cookie fully determined successfully, computing admin password'
    password = hashlib.sha256(_USERNAME + formatted_cookie).hexdigest()
    print 'Password for \'{}\': {}'.format(_USERNAME, password)
    with contextlib.closing(socket.socket()) as sock:
        sock.connect(('localhost', 9006))
        sock.sendall('{}\n{}\n'.format(_USERNAME, password))
        while True:
            received = sock.recv(512)
            if not received:
                break
            print received
else:
    print 'Cookie still has variability, add more pre-recorded requests'
```
he connected to the server from another `ssh` user.
then he corrupted the second block's hyphen and tried to corrupt the cookie byte to be the new hyphen. Then he checked if the message is has 2 hyphens he guessed correctly.
## ariel
same method as I did but used an array of offsets
```python
# Created by H4$hBr0wn1e

import socket, os
import hashlib, base64

server_addr = ("143.248.249.64", 9006) # Change to 127.0.0.1 in local server
guest_pw = "8b465d23cb778d3636bf6c4c5e30d031675fd95cec7afea497d36146783fd3a1"
br = '#' * 100


def clean(msg, n):
	return msg[msg.index('(') + 1:msg.index(')')].decode('hex')[:n]

def new_con():
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(server_addr)
	return sock

def main():
	# Initialize arrays and values
	n = [0 for _ in xrange(64)]
	c = r = ['' for _ in xrange(64)]
	n[0] = 13 + 16 * 4
	m = 0

	while True:
		print 'Round', str(m + 1)
		# Create connection
		sock = new_con()

		# Get server intro message
		sock.recv(1024)

		# Get real value
		# sock.recv(64)			# Get ID message
		sock.send('a' * n[m] + '\n')	# Send ID message
		sock.recv(64) 			# Get password message
		sock.send('\n')			# Send empty password

		# Store the real value of the encryption for comparison
		r[m] = clean(sock.recv(2048), n[m] + 2 + m)
		sock.close()

		# Go through all the possible choices of char for cookie
		for cand in '1234567890abcdefghijklmnopqrstuvwxyz-_':
			# Create connection
			sock = new_con()
			
			sock.recv(1024)						# Get server intro message
			# sock.recv(64)						# Get ID message
			sock.send('a' * n[m] + '--' + c[m-1] + cand + '\n') 	# Send candidate as id
			sock.recv(64)						# Get password message
			sock.send('\n')						# Send empty password

			# Check if new byte found
			if clean(sock.recv(2048), n[m] + 2 + m) == r[m]:
				c[m] = c[m-1] + cand
				print "New candidate found :\t ", cand
				print "Current cookie :\t ", c[m]
				sock.close()
				break

		# Check If the password found
		if hashlib.sha256('guest' + c[m]).hexdigest() == guest_pw:
			print '\n' + br +'\n\nCookie found!!!\n\n' + br + '\n', c[m]

			# Get the flag
			sock = new_con()				# Create connection
			print "Capturing the flag.",
			sock.recv(1024)					# Get server intro message
			print ".",
			# sock.recv(64)					# Get ID message
			sock.send('admin'+ '\n') 			# Send ID
			print ".",
			sock.recv(64)					# Get password message
			print ".",
			pw = hashlib.sha256('admin' + c[m]).hexdigest()	# Calculate password
			print ".",
			sock.send(pw + '\n')				# Send password
			print "."

			# Check if flag found and exit
			sock.recv(512)
			print br +'\n\nFlag found!!!\n\n' + br + '\n', sock.recv(512)
			sock.close()
			os._exit(0)

		# Update values
		n[m + 1] = n[m] - 1
		m += 1

if __name__ == '__main__':
	main()

```

# learning
## the right thinking flow
1. the password is hash of the id+cookie, so we need to get the cookie
2. the cookie is send every request, which is encrypted with AES CBC 128 bits. So if I will decrypt the message I win
3. You can break AEC CBC by 1) changing the ciphertext; 2) guessing one byte from the cookie by changing the plaintext
4. the second option seems simpler. And it works :)
## time spent
thinking the direction is not valid because it didn't work. But the problem was my implementation, 
and if I would have checked why it didn't work I would have solve this challenge faster.
