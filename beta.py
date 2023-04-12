import asyncio
import subprocess
from concurrent.futures import ProcessPoolExecutor
import concurrent.futures


cmds = [

        f"subfinder -t 100 -all -d safetypay.com 2> /dev/null > passive.txt",
        f"assetfinder --subs-only safetypay.com 2> /dev/null >> passive.txt",
    ]

async def active_enumeration(domain):
    print("Active Enum Executed")
    cmd = f"puredns bruteforce ~/best-dns-wordlist.txt {domain} -q -r ~/resolvers.txt 2> /dev/null > active.txt"
    process = await asyncio.create_subprocess_shell(cmd)
    return process

async def run_passive_enumeration(cmd):
    print("Passive Enum Executed",cmd)
    process = await asyncio.create_subprocess_shell(cmd)
    return process


async def passive_enumeration():
    tasks = []
    for cmd in cmds:
        task = asyncio.create_task(run_passive_enumeration(cmd))
        tasks.append(task)
    return tasks

async def run_resolving(hostsfile=['passive','prem_passive']):
    print("Resolving Executed")
    cmd = f"cat passive.txt perm_passive.txt | sort -u | puredns resolve -q -r ~/resolvers.txt > resolved_passive.txt"
    process = await asyncio.create_subprocess_shell(cmd)
    return process


async def run_permutation(hostsfile="passive"):
    print("Permutation is Started")
    cmd = f"gotator -sub {hostsfile}.txt -perm=/root/perm.txt -depth=1 -prefixes -mindup -adv -silent -t=200 > perm_{hostsfile}.txt"
    process = await asyncio.create_subprocess_shell(cmd)
    return process

async def run_portscan(hostsfile="passive"):
    print("PortScaning is Started")
    cmd = f"unimap -f resolved_passive.txt -q --ports '81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672,80,443' --min-rate 2500 --fast-scan --url-output > webports_passive.txt"
    process = await asyncio.create_subprocess_shell(cmd)
    return process

async def run_httpprobe(hostsfile="passive"):
    print("Httpprobeing is Started")
    cmd = "cat resolved_passive.txt | httpx -silent -t 200 > httpx.txt"
    process = await asyncio.create_subprocess_shell(cmd)
    return process

async def run_tls():
    print("tls scanning is Started")
    cmd = "cat httpx.txt | tlsx -san -cn -silent -resp-only -c 500 | sort -u > crt.txt"
    process = await asyncio.create_subprocess_shell(cmd)
    return process

async def clean():
    print("tls scanning is Started")
    cmd = "rm -v !('filename1'|'filename2')"
    process = await asyncio.create_subprocess_shell(cmd)
    return process


async def run_tasks():
    d = "bitthebyte.com"
    active_enum  = await asyncio.create_task(active_enumeration(d))
    passive_enum = await asyncio.create_task(passive_enumeration())
    for task in passive_enum:
        process = await task
        await process.wait()
    passive_perm = await asyncio.create_task(run_permutation())
    await passive_perm.wait()
    passive_resolve = await asyncio.create_task(run_resolving())
    await passive_resolve.wait()
    passive_portscan = await asyncio.create_task(run_portscan())
    await passive_portscan.wait()
    passive_httpprobing = await asyncio.create_task(run_httpprobe())
    await passive_httpprobing.wait()
    passive_tls_scan = await asyncio.create_task(run_tls())
    await passive_tls_scan.wait()
    print("Awiting for active")
    await active_enum.wait()
    print("active_enum Finshed")
    #cleanup = await asyncio.create_task(clean())
    #await cleanup.wait()
    #print("Cleanup Finshed")

if __name__ == "__main__":
    asyncio.run(run_tasks())
