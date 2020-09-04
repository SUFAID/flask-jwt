n1 = int(input("Enter Starting Number:"))
n2 = int(input("Enter Ending number:"))

def is_prime(num):
    for i in range(2, int(num/2+1)):
        if (num % i) == 0:
           return False
    return True

for i in range(n1+1,n2):
	if is_prime(i):
		print(i)
