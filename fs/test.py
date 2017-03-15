#! /usr/bin/python  
import os  
import re  
pth=raw_input("Path:")    
rule="^\(static|\(static inline \)|struct|i*\)\s*\<\w\+\s\+\(*|\)\w\+\s*([^)]*)\s*\s*$"  
for parent,dirnames,filenames in os.walk(pth):    
    for filename in filenames:  
        ext = os.path.splitext(filename)[1][1:]  
        if ext == "cpp" or ext=="c":  
            f=open(os.path.join(parent, filename))  
            lc=0  
            while 1:  
                li=f.readline()  
                lc+=1  
                if not li: break  
                if re.match(rule,li):  
                    print os.path.join(parent, filename),' @',lc  
            f.close()
