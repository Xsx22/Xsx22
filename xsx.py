
print ("++++ Network Scanner |X|S|X| +++++++") 

print ("++++[Network security]++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++(2022)+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++") 

print ("--------------[system information]-------------------------------------------------------------------") 

import socket
print([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] 
if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), 
s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, 
socket.SOCK_DGRAM)]][0][1]]) if l][0][0])




import socket
h_name = socket.gethostname()
IP_addres = socket.gethostbyname(h_name)
print("Host Name is:" + h_name)
print("Computer IP Address is:" + IP_addres)

import uuid
# after each 2 digits, join elements of getnode().
print ("The formatted MAC address is : ", end="")
print (':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
for elements in range(0,2*6,2)][::-1]))




import time
now = time.time()
# print(now)
time_str = time.ctime(now)
print(time_str)




print ("-----------------[scan port]--------------------------------------------------------------------------------")



from socket import *
import time
startTime = time.time()

if __name__ == '__main__':
   target = input('Enter the host to be scanned: ')
   t_IP = gethostbyname(target)
   print ('Starting scan on host: ', t_IP)
   
   for i in range(50, 500):
      s = socket(AF_INET, SOCK_STREAM)
      
      conn = s.connect_ex((t_IP, i))
      if(conn == 0) :
         print ('Port %d: OPEN' % (i,))
      s.close()
print('Time taken:', time.time() - startTime)




print ("-----------------[information about the network interfaces and their status..]--------------------------------------------------------------------------")




from netifaces import interfaces, ifaddresses, AF_INET
for ifaceName in interfaces():
    addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
    print('%s: %s' % (ifaceName, ', '.join(addresses)))
	

print ("----------------[network connections].---------------") 

from netifaces import interfaces, ifaddresses, AF_INET
for ifaceName in interfaces():
    addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
    print(' '.join(addresses))

print ("--------------------------------------") 

print ("-----------------[Network Scanner]----Security >>>>----------------------------") 

import scapy.all as scapy
  
request = scapy.ARP()
print(request.summary())


import scapy.all as scapy
  
request = scapy.ARP()
print(request.show())