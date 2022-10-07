'''
The Clear BSD License

Copyright (c) 2022 Stanley Chen
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted (subject to the limitations in the disclaimer below) provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

     * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

     * Neither the name of Stanley Chen nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'''

import sys
import re
from math import floor, log2
from argparse import ArgumentParser

class Cidr:
    def __init__(self):
        self.limit = 4294967295     # int('11111111111111111111111111111111',2)
    def check_ip_int(self, a: int) -> bool:
        return a > 0 and a <= self.limit
    def check_ip_str(self, ip:str):
        if re.match(r"\d{1,3}(\.\d{1,3}){3}", ip) == None:
            raise ValueError(f"Error: invalid IPv4 address. Got {ip}")
            return False
        return True    
    def check_cidr_bitmask(self, cidr_bitmask: int) -> bool:
        if cidr_bitmask < 1 or cidr_bitmask > 32: 
            #print(f"Error: cidr mask bits must be between 1 to 32. Got {cidr_bitmask}")
            raise ValueError(f"Error: cidr mask bits must be between 1 to 32. Got {cidr_bitmask}")
            return False
        return True
    # normalize ip into cidr notation
    def normalize(self, ip: str):
        self.check_ip_str(ip)
        if ip.find('/') == -1: 
            return ip + "/32"
        return ip

    def to_subnet_mask(self, cidr_bitmask: int):
        return self.limit << 32 - cidr_bitmask

    #ip address to integer
    def ip_to_int(self, ip: str):
        self.check_ip_str(ip)
        #string -> binary -> init
        octects = [ format(int(x), '08b') for x in ip.split('.', 4)]
        return int("".join(octects), 2)

    # format to dot notation, with optional cidr bitmask     
    def dot_notation(self, v: int, cidr_bitmask :int = None):
        s = format(v, '032b')
        x = [s[i:i + 8] for i in range(0, len(s), 8)]
        xs = [ str(int(b, 2)) for b in x]
        if cidr_bitmask: 
            self.check_cidr_bitmask(cidr_bitmask)
            return  ".".join(xs) + "/" + str(cidr_bitmask)

        return ".".join(xs)

    # split ip into: ip integer and cidr integer
    def split_cidr(self, ip: str):
        ip = self.normalize(ip)
        (dot_notation, cidr_bitmask) = ip.split('/', 2)
        try: 
            ip_int = self.ip_to_int(dot_notation)
        except ValueError:
            raise ValueError(f"Error: invalid IPv4 address. Got {ip}")
            
        if not self.check_ip_int(ip_int):
            raise ValueError(f"Error: invalid IPv4 address. Got {ip}")
        if cidr_bitmask == None:
            cidr_bitmask = 32
        cidr_bitmask = int(cidr_bitmask)
        self.check_cidr_bitmask(cidr_bitmask)
        return [ip_int, cidr_bitmask]

    # given an ip address or a cidr, return start and end of the ip range in numeric.
    def ip_range_int(self, ip: str):
        (ip_, cidr) = self.split_cidr(ip)
        mask = self.to_subnet_mask(cidr)
        n = 2 ** (32 - cidr)    # total number of addresses in the range
        start = ip_ & mask
        end = start + n - 1
        return [start, end]
    
    def ip_range_dot_notation(self, ip: str):
        (a, b) = self.ip_range_int(ip)
        return [self.dot_notation(a), self.dot_notation(b)]

    # given an IP numberic range, return a list of cidr blocks represent the range
    def ip_range_to_cidrs(self, start: int, end: int):
        c_blocks = []
        if start == end: 
            return [ self.dot_notation(start) + "/32" ]
        else:
            pow2 = floor(log2(end - start + 1))
            # find the largest cidr block that also begin with start ip; 
            for n in range(pow2, 0, -1):
                cidr = self.dot_notation(start, 32 - n )
                (start_, end_) = self.ip_range_int(cidr)
                if start_ ==  start:
                    break
            if start_ < start:   # loop exhausted, but didn't find a cidr block matching start, add start/32
                 c_blocks.append(self.dot_notation(start, 32))
            else: 
                # this is the largest cidr block begining with ip that's the same as start, save it.    
                c_blocks.append(cidr)
            if end_ < end: 
                #  calculate next cidr block.
                c_blocks += self.ip_range_to_cidrs(end_ + 1, end)

        return c_blocks

    def ip_str_range_to_cidrs(self, a: str, b: str):
        return self.ip_range_to_cidrs(self.ip_to_int(a), self.ip_to_int(b))


    def merge_overlap(self, ip_range_list: list):
        ip_range_list.sort(key=lambda n: n[0])    #sort by start 
        m = []
        for x in ip_range_list:
            if len(m) == 0 or m[-1][1] + 1 < x[0] :
                m.append((x)) 
            else:   # overlap, merge two ranges, 
                if x[1] > m[-1][1]:
                    m[-1][1] = x[1]
        return m

    # given a list of cidr addresses, return a minimal list that represent the same.      
    def pack(self, cidr_list: list):
        ip_range_list = [ self.ip_range_int(cidr) for cidr in cidr_list ] 
        merged_list = self.merge_overlap(ip_range_list)
        cidr_list = []
        for start, end in merged_list:
            cidr_list += self.ip_range_to_cidrs(start, end)
        return cidr_list
    
    #given a list of cidr, unpack will return a list of every single IP address.
    # useful to test the pack function:  unpack(original_list) == unpack(pack(original_list))
    def unpack(self, cidr_list: list):
        ips = {}
        for cidr in cidr_list:
            (start, end) = self.ip_range_int(cidr)
            if start == end:
                ips[self.dot_notation(start)] = 1
                continue    
            for ip_int in range(start, end + 1, 1):
                ips[self.dot_notation(ip_int)] = 1
        return list(ips.keys())
    
if __name__ == "__main__":
    p = ArgumentParser(description="cidr address manipulation")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-v", "--verbose", action="store_true")
    g.add_argument("-q", "--quiet", action="store_true")
    g2 = p.add_mutually_exclusive_group()
    g2.add_argument("-p", "--pack", action="store_true", help="pack a given list of cidr addresses")
    g2.add_argument("-t", "--test-pack", action="store_true",  help="pack a given list of cidr addresses and run test cases")
    g2.add_argument("-u", "--unpack", action="store_true", help="expand cidr list into individual ip address")
    g2.add_argument("-r", "--ip-range-to-cidr", action="store_true", help="convert an ip range to cidr lists")

    p.add_argument("addresses",  type=str,  help="a list represent cidr blocks or an ip range")
    
    co = p.parse_args()
    #print(f"{co}")
    
    cidr = Cidr()
    r = [] 
    if co.ip_range_to_cidr:
        (start, end) = co.addresses.split(',', 2)
        print("\n".join(cidr.ip_str_range_to_cidrs(start, end)))
        sys.exit(0)
    cidr_list = co.addresses.split(',')
    if co.pack:
        r = cidr.pack(cidr_list)
        print("\n".join(r))
    if co.test_pack:
        t = {}
        r = cidr.pack(cidr_list)
        ips = cidr.unpack(cidr_list)
        for ip in ips:
            t[ip] = 1
        _ips = cidr.unpack(r)
        for _ip in _ips:
            if not _ip in t: 
                if co.verbose:
                    print(f"test case failed.  Unmatched ip: { _ip}")
                sys.exit(1)
            del t[_ip]
        
        if len(t):
            if co.verbose:
                print(f"test case failed.  Unmatched ip: { list(t.keys()) }")
            sys.exit(1)
        else:
            if co.verbose:
                print('test case passed')
            print("\n".join(r))
            sys.exit(0)
    
    if co.unpack:
        print("\n".join(cidr.unpack(cidr_list)))
